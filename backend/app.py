from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import pickle
import pandas as pd
from datetime import datetime
from create_model import RuleBasedStalenessDetector
import logging
import json
from typing import Dict, List, Optional
import os
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, 
     origins=['https://royo1019.github.io/royoplay/', 
              'http://localhost:5173', 
              'http://localhost:5174', 
              'https://lightcoral-loris-143961.hostingersite.com',
              'https://lightcoral-loris-143961.hostingersite.com/'],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'OPTIONS'],
     expose_headers=['Content-Type'],
     max_age=3600)

# Load the ML model
MODEL_PATH = 'staleness_detector_model.pkl'
model = None

# Store assignment history in memory (in production this should be in a database)
assignment_history = []

# Configure retry strategy
retry_strategy = Retry(
    total=3,  # number of retries
    backoff_factor=1,  # wait 1, 2, 4 seconds between retries
    status_forcelist=[408, 429, 500, 502, 503, 504]  # HTTP status codes to retry on
)
http_adapter = HTTPAdapter(max_retries=retry_strategy)

def create_session():
    """Create a requests session with retry logic"""
    session = requests.Session()
    session.mount("http://", http_adapter)
    session.mount("https://", http_adapter)
    return session

def load_model():
    """Load the pickle model"""
    global model
    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        logger.info(f"Model loaded successfully from {MODEL_PATH}")
        return True
    except Exception as e:
        logger.error(f"Failed to load model: {str(e)}")
        return False

# Load model on startup
load_model()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'CMDB Analyzer Backend',
        'model_loaded': model is not None
    })

@app.route('/test-connection', methods=['POST'])
def test_connection():
    """Test ServiceNow connection endpoint"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['instance_url', 'username', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'error': f'Missing required field: {field}'
                }), 400
        
        instance_url = data['instance_url'].rstrip('/')
        username = data['username']
        password = data['password']
        
        # Test ServiceNow connection
        logger.info(f"Testing connection to {instance_url}")
        
        test_url = f"{instance_url}/api/now/table/sys_user"
        
        try:
            response = requests.get(
                test_url,
                auth=(username, password),
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                params={'sysparm_limit': '1'},
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info("ServiceNow connection successful")
                return jsonify({
                    'success': True,
                    'message': 'Connection successful!',
                    'timestamp': datetime.now().isoformat()
                })
                
            elif response.status_code == 401:
                return jsonify({
                    'success': False,
                    'error': 'Authentication failed. Please check your credentials.'
                }), 401
                
            elif response.status_code == 403:
                return jsonify({
                    'success': False,
                    'error': 'Access denied. User may not have required permissions.'
                }), 403
                
            else:
                return jsonify({
                    'success': False,
                    'error': f'ServiceNow API error: {response.status_code}'
                }), 400
                
        except requests.exceptions.Timeout:
            return jsonify({
                'success': False,
                'error': 'Connection timeout. Please check the instance URL and try again.'
            }), 408
            
        except requests.exceptions.ConnectionError:
            return jsonify({
                'success': False,
                'error': 'Cannot connect to ServiceNow instance. Please verify the URL.'
            }), 503
            
        except requests.exceptions.RequestException as e:
            return jsonify({
                'success': False,
                'error': f'Request failed: {str(e)}'
            }), 500
    
    except Exception as e:
        logger.error(f"Unexpected error in test connection: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error occurred'
        }), 500

@app.route('/scan-stale-ownership', methods=['POST'])
def scan_stale_ownership():
    """
    Scan and analyze CIs for stale ownership using ML model
    """
    if model is None:
        return jsonify({
            'error': 'ML model not loaded. Please check server logs.'
        }), 500

    try:
        data = request.get_json()
        logger.info(f"scan_stale_ownership input: {data}")
        instance_url = data.get('instance_url')
        username = data.get('username')
        password = data.get('password')
        
        # Debug: Check credentials (mask password)
        logger.info(f"Received credentials - URL: {instance_url}, Username: {username}, Password: {'*' * len(password) if password else 'None'}")
        
        if not instance_url or not username or not password:
            return jsonify({'error': 'Missing required credentials'}), 400

        # Fetch data from ServiceNow
        logger.info("Fetching data from ServiceNow...")
        
        # Get CI data
        ci_data = fetch_ci_data(instance_url, username, password, limit=100000000)
        logger.info(f"Fetched {len(ci_data)} CI records")
        if not ci_data:
            logger.error("No CI data fetched")
            return jsonify({'error': 'Failed to fetch CI data'}), 500

        # Get audit data
        audit_data = fetch_audit_data(instance_url, username, password, limit=200000000)
        logger.info(f"Fetched {len(audit_data)} audit records")
        if not audit_data:
            logger.error("No audit data fetched")
            return jsonify({'error': 'Failed to fetch audit data'}), 500

        # Get user data
        user_data = fetch_user_data(instance_url, username, password, limit=500000)
        logger.info(f"Fetched {len(user_data)} user records")
        if not user_data:
            logger.error("No user data fetched")
            return jsonify({'error': 'Failed to fetch user data'}), 500

        logger.info(f"Fetched {len(ci_data)} CIs, {len(audit_data)} audit records, {len(user_data)} users")

        # Process data and make predictions
        try:
            stale_ci_list = analyze_cis_with_model(ci_data, audit_data, user_data)
        except Exception as model_exc:
            logger.error(f"Error in analyze_cis_with_model: {str(model_exc)}", exc_info=True)
            return jsonify({
                "error": f"Model analysis failed: {str(model_exc)}"
            }), 500

        # Group stale CIs by recommended owners
        grouped_by_owners = group_cis_by_recommended_owners(stale_ci_list)

        return jsonify({
            'success': True,
            'message': 'Analysis completed successfully',
            'summary': {
                'total_cis_analyzed': len(ci_data),
                'stale_cis_found': len(stale_ci_list),
                'high_confidence_predictions': sum(1 for ci in stale_ci_list if ci['confidence'] > 0.8),
                'critical_risk': sum(1 for ci in stale_ci_list if ci['risk_level'] == 'Critical'),
                'high_risk': sum(1 for ci in stale_ci_list if ci['risk_level'] == 'High'),
                'recommended_owners_count': len(grouped_by_owners)
            },
            'stale_cis': stale_ci_list,
            'grouped_by_owners': grouped_by_owners
        })

    except Exception as e:
        logger.error(f"Error in scan_stale_ownership: {str(e)}", exc_info=True)
        return jsonify({
            "error": f"Scan failed: {str(e)}"
        }), 500

def fetch_ci_data(instance_url, username, password, limit=10000):
    """Fetch CI data from ServiceNow"""
    try:
        url = f"{instance_url}/api/now/table/cmdb_ci"
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(
            url,
            auth=(username, password),
            headers=headers,
            params={
                'sysparm_limit': limit,
                'sysparm_fields': 'sys_id,name,short_description,sys_class_name,sys_updated_on,assigned_to,assigned_to.user_name,assigned_to.name,assigned_to.sys_id',
                'sysparm_display_value': 'all'
            },
            timeout=60
        )
        
        if response.status_code == 200:
            try:
                json_data = response.json()
                result = json_data.get('result', [])
                if not isinstance(result, list):
                    logger.error(f"CI data result is not a list: {type(result)} - {result}")
                    return []
                logger.info(f"Successfully fetched {len(result)} CI records")
                return result
            except (ValueError, KeyError) as e:
                logger.error(f"Failed to parse CI data JSON: {str(e)} - Response: {response.text[:500]}")
                return []
        else:
            logger.error(f"Failed to fetch CI data: {response.status_code} - {response.text[:500]}")
            return []
            
    except Exception as e:
        logger.error(f"Error fetching CI data: {str(e)}")
        return []

def fetch_audit_data(instance_url, username, password, limit=20000):
    """Fetch audit data from ServiceNow including user profile changes"""
    try:
        # Fetch CI-related audit records
        ci_audit_data = fetch_ci_audit_records(instance_url, username, password, limit)
        
        # Fetch user profile audit records (title, department changes)
        user_audit_data = fetch_user_audit_records(instance_url, username, password, limit // 2)
        
        # Combine both datasets
        combined_audit_data = ci_audit_data + user_audit_data
        
        logger.info(f"Combined audit data: {len(ci_audit_data)} CI records + {len(user_audit_data)} user profile records = {len(combined_audit_data)} total")
        return combined_audit_data
            
    except Exception as e:
        logger.error(f"Error fetching audit data: {str(e)}")
        return []

def fetch_ci_audit_records(instance_url, username, password, limit=15000):
    """Fetch CI-related audit records from ServiceNow"""
    try:
        url = f"{instance_url}/api/now/table/sys_audit"
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        # Get recent audit records for CI table changes
        response = requests.get(
            url,
            auth=(username, password),
            headers=headers,
            params={
                'sysparm_limit': limit,
                'sysparm_fields': 'sys_created_on,tablename,fieldname,documentkey,user,user.user_name,user.name,user.sys_id,oldvalue,newvalue',
                'sysparm_display_value': 'all',
                'sysparm_query': 'tablename=cmdb_ci^ORtablename=cmdb_ci_server^ORtablename=cmdb_ci_computer^ORtablename=cmdb_ci_linux_server^ORtablename=cmdb_ci_win_server'
            },
            timeout=120
        )
        
        if response.status_code == 200:
            try:
                json_data = response.json()
                result = json_data.get('result', [])
                if not isinstance(result, list):
                    logger.error(f"CI audit data result is not a list: {type(result)} - {result}")
                    return []
                logger.info(f"Successfully fetched {len(result)} CI audit records")
                return result
            except (ValueError, KeyError) as e:
                logger.error(f"Failed to parse CI audit data JSON: {str(e)} - Response: {response.text[:500]}")
                return []
        else:
            logger.error(f"Failed to fetch CI audit data: {response.status_code} - {response.text[:500]}")
            return []
            
    except Exception as e:
        logger.error(f"Error fetching CI audit data: {str(e)}")
        return []

def fetch_user_audit_records(instance_url, username, password, limit=10000):
    """Fetch user profile audit records (title, department changes) from ServiceNow"""
    try:
        url = f"{instance_url}/api/now/table/sys_audit"
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        # First, let's get a broader set of sys_user audit records to see what's available
        test_response = requests.get(
            url,
            auth=(username, password),
            headers=headers,
            params={
                'sysparm_limit': 100,
                'sysparm_fields': 'tablename,fieldname,documentkey',
                'sysparm_query': 'tablename=sys_user'
            },
            timeout=30
        )
        
        if test_response.status_code == 200:
            test_data = test_response.json().get('result', [])
            field_counts = {}
            for record in test_data:
                field = record.get('fieldname', {})
                if isinstance(field, dict):
                    field = field.get('value', field.get('display_value', ''))
                field_counts[field] = field_counts.get(field, 0) + 1
            logger.info(f"Available sys_user audit fields (sample of 100): {field_counts}")
        
        # Get user profile change records - cast a wider net to capture all profile changes
        # Based on the ServiceNow UI, we can see many more field types than just title/department
        response = requests.get(
            url,
            auth=(username, password),
            headers=headers,
            params={
                'sysparm_limit': limit,
                'sysparm_fields': 'sys_created_on,tablename,fieldname,documentkey,user,user.user_name,user.name,user.sys_id,oldvalue,newvalue',
                'sysparm_display_value': 'all',
                # Expanded query to include more profile change fields observed in the ServiceNow UI
                'sysparm_query': 'tablename=sys_user^fieldnameINtitle,department,manager,active,job_title,u_job_title,cost_center,location,company,u_account_type,u_team_structure,u_compliance_certified,u_additional_responsibilities,u_vendor_status,u_work_arrangement,u_coverage_status,u_employee_type,building,employee_number,u_leave_type,skills,u_acquisition_date,vip,u_specialization,u_on_call,locked_out,last_login_time,u_focus_area,u_methodology,u_service_model,u_additional_servers^sys_created_onONLast 90 days@javascript:gs.daysAgoStart(90)@javascript:gs.daysAgoEnd(0)'
            },
            timeout=120
        )
        
        if response.status_code == 200:
            try:
                json_data = response.json()
                result = json_data.get('result', [])
                if not isinstance(result, list):
                    logger.error(f"User audit data result is not a list: {type(result)} - {result}")
                    return []
                
                # Add a marker to distinguish user profile changes
                for record in result:
                    record['audit_type'] = 'user_profile_change'
                
                logger.info(f"Successfully fetched {len(result)} user profile audit records")
                
                # Debug: Log sample of user profile changes
                if result:
                    logger.info("Sample user profile audit records:")
                    for i, record in enumerate(result[:5]):  # Show first 5
                        logger.info(f"  Record {i}: tablename={record.get('tablename')}, fieldname={record.get('fieldname')}, "
                                  f"documentkey={record.get('documentkey')}, oldvalue={record.get('oldvalue')}, "
                                  f"newvalue={record.get('newvalue')}")
                
                # Count by field type
                field_breakdown = {}
                for r in result:
                    field = r.get('fieldname')
                    if isinstance(field, dict):
                        field = field.get('value', field.get('display_value', ''))
                    field_breakdown[field] = field_breakdown.get(field, 0) + 1
                
                logger.info(f"Profile changes breakdown by field: {field_breakdown}")
                
                # Debug: Show all records if there are few
                if len(result) <= 50:
                    logger.info("All user profile audit records (since there are few):")
                    for i, record in enumerate(result):
                        doc_key = record.get('documentkey', {})
                        if isinstance(doc_key, dict):
                            doc_key_val = doc_key.get('value', doc_key.get('display_value', ''))
                        else:
                            doc_key_val = doc_key
                        
                        # Get table name to verify filtering
                        table_name = record.get('tablename', {})
                        if isinstance(table_name, dict):
                            table_name_val = table_name.get('value', table_name.get('display_value', ''))
                        else:
                            table_name_val = table_name
                        
                        logger.info(f"  Record {i}: tablename={table_name_val}, fieldname={record.get('fieldname')}, "
                                  f"documentkey={doc_key_val}, "
                                  f"oldvalue={record.get('oldvalue')}, "
                                  f"newvalue={record.get('newvalue')}, "
                                  f"created={record.get('sys_created_on')}")
                
                # Additional verification - count by table name to ensure we only got sys_user
                table_counts = {}
                for r in result:
                    table = r.get('tablename')
                    if isinstance(table, dict):
                        table = table.get('value', table.get('display_value', ''))
                    table_counts[table] = table_counts.get(table, 0) + 1
                
                logger.info(f"Records by table name: {table_counts}")
                if len(table_counts) > 1 or 'sys_user' not in table_counts:
                    logger.warning(f"Expected only sys_user records, but got: {table_counts}")
                
                return result
            except (ValueError, KeyError) as e:
                logger.error(f"Failed to parse user audit data JSON: {str(e)} - Response: {response.text[:500]}")
                return []
        else:
            logger.error(f"Failed to fetch user audit data: {response.status_code} - {response.text[:500]}")
            return []
            
    except Exception as e:
        logger.error(f"Error fetching user audit data: {str(e)}")
        return []

def fetch_user_data(instance_url, username, password, limit=5000):
    """Fetch user data from ServiceNow"""
    try:
        url = f"{instance_url}/api/now/table/sys_user"
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(
            url,
            auth=(username, password),
            headers=headers,
            params={
                'sysparm_limit': limit,
                'sysparm_fields': 'sys_id,user_name,name,email,active,sys_created_on,department'
            },
            timeout=60
        )
        
        if response.status_code == 200:
            try:
                json_data = response.json()
                result = json_data.get('result', [])
                if not isinstance(result, list):
                    logger.error(f"User data result is not a list: {type(result)} - {result}")
                    return []
                logger.info(f"Successfully fetched {len(result)} user records")
                return result
            except (ValueError, KeyError) as e:
                logger.error(f"Failed to parse user data JSON: {str(e)} - Response: {response.text[:500]}")
                return []
        else:
            logger.error(f"Failed to fetch user data: {response.status_code} - {response.text[:500]}")
            return []
            
    except Exception as e:
        logger.error(f"Error fetching user data: {str(e)}")
        return []

def analyze_cis_with_model(ci_data, audit_data, user_data):
    """Analyze CIs using the ML model and return stale CI list"""
    
    # Validate data types before creating DataFrames
    logger.info(f"Data validation - CI data type: {type(ci_data)}, length: {len(ci_data) if isinstance(ci_data, list) else 'N/A'}")
    logger.info(f"Data validation - Audit data type: {type(audit_data)}, length: {len(audit_data) if isinstance(audit_data, list) else 'N/A'}")
    logger.info(f"Data validation - User data type: {type(user_data)}, length: {len(user_data) if isinstance(user_data, list) else 'N/A'}")
    
    # Check if data is valid
    if not isinstance(ci_data, list) or not ci_data:
        logger.error(f"CI data is not a valid list: {type(ci_data)} - {ci_data}")
        raise ValueError("CI data must be a non-empty list of dictionaries")
        
    if not isinstance(audit_data, list):
        logger.error(f"Audit data is not a valid list: {type(audit_data)} - {audit_data}")
        raise ValueError("Audit data must be a list of dictionaries")
        
    if not isinstance(user_data, list):
        logger.error(f"User data is not a valid list: {type(user_data)} - {user_data}")
        raise ValueError("User data must be a list of dictionaries")
    
    # Transform string items to dictionaries where needed
    def transform_to_dict(data, data_type):
        """Transform string items to dictionaries"""
        transformed = []
        for i, item in enumerate(data):
            if isinstance(item, str):
                logger.warning(f"{data_type} item {i} is a string, converting to dict: {item[:100]}...")
                
                # Try to parse as JSON first (in case it's a JSON string)
                try:
                    parsed_item = json.loads(item)
                    if isinstance(parsed_item, dict):
                        logger.info(f"Successfully parsed {data_type} item {i} as JSON")
                        transformed.append(parsed_item)
                        continue
                except (json.JSONDecodeError, ValueError):
                    pass
                
                # If not JSON, create a basic dictionary structure for string data
                transformed.append({
                    'raw_data': item,
                    'data_type': 'string_converted',
                    'index': i,
                    'original_length': len(item)
                })
            elif isinstance(item, dict):
                transformed.append(item)
            else:
                logger.warning(f"{data_type} item {i} is unexpected type {type(item)}, converting to dict")
                transformed.append({
                    'raw_data': str(item),
                    'data_type': f'{type(item).__name__}_converted',
                    'index': i
                })
        return transformed
    
    # Transform data if needed
    logger.info(f"Before transformation - CI: {len(ci_data)} items, Audit: {len(audit_data)} items, User: {len(user_data)} items")
    
    ci_data = transform_to_dict(ci_data, "CI")
    audit_data = transform_to_dict(audit_data, "Audit") 
    user_data = transform_to_dict(user_data, "User")
    
    logger.info(f"After transformation - CI: {len(ci_data)} items, Audit: {len(audit_data)} items, User: {len(user_data)} items")
    
    # Log sample of transformed data for debugging
    if audit_data:
        logger.info(f"Sample transformed audit data: {audit_data[0]}")
        # Count how many were converted from strings
        string_converted = sum(1 for item in audit_data if item.get('data_type') == 'string_converted')
        if string_converted > 0:
            logger.warning(f"Converted {string_converted} audit items from strings to dictionaries")
    
    # Convert to pandas DataFrames
    try:
        ci_df = pd.DataFrame(ci_data)
        logger.info(f"Created CI DataFrame with shape: {ci_df.shape}")
    except Exception as e:
        logger.error(f"Error creating CI DataFrame: {str(e)}")
        raise ValueError(f"Failed to create CI DataFrame: {str(e)}")
        
    try:
        audit_df = pd.DataFrame(audit_data)
        logger.info(f"Created audit DataFrame with shape: {audit_df.shape}")
    except Exception as e:
        logger.error(f"Error creating audit DataFrame: {str(e)}")
        raise ValueError(f"Failed to create audit DataFrame: {str(e)}")
        
    try:
        user_df = pd.DataFrame(user_data)
        logger.info(f"Created user DataFrame with shape: {user_df.shape}")
    except Exception as e:
        logger.error(f"Error creating user DataFrame: {str(e)}")
        raise ValueError(f"Failed to create user DataFrame: {str(e)}")
    
    # Log a sample CI for debugging
    if len(ci_data) > 0:
        sample_ci = ci_data[0]
        logger.info(f"Sample CI keys: {list(sample_ci.keys())}")
        logger.info(f"Sample CI name: {sample_ci.get('name', 'N/A')}")
        if 'assigned_to' in sample_ci:
            logger.info(f"Sample CI assigned_to structure: {sample_ci['assigned_to']}")
            logger.info(f"Sample CI assigned_to type: {type(sample_ci['assigned_to'])}")
        else:
            logger.info("No assigned_to field found in sample CI")
    
    # Log sample audit data
    if len(audit_data) > 0:
        logger.info(f"Sample audit record: {audit_data[0]}")
        
    # Log sample user data
    if len(user_data) > 0:
        sample_user = user_data[0]
        logger.info(f"Sample user keys: {list(sample_user.keys())}")
        logger.info(f"Sample user name: {sample_user.get('name', 'N/A')}")
        logger.info(f"Sample user user_name: {sample_user.get('user_name', 'N/A')}")
        logger.info(f"Sample user sys_id: {sample_user.get('sys_id', 'N/A')}")
    
    # Create labels DataFrame from CI data
    labels_data = []
    ci_owner_display_names = {}  # Map CI ID to owner display name for later use
    user_by_sys_id = {}  # Create mapping by sys_id for better lookup
    user_by_name = {}    # Create mapping by username for better lookup
    
    # Build user mappings for better display name resolution
    for user in user_data:
        if user.get('sys_id'):
            user_by_sys_id[user.get('sys_id')] = user
        if user.get('user_name'):
            user_by_name[user.get('user_name')] = user
    
    for ci in ci_data:
        assigned_to = ci.get('assigned_to', None)
        assigned_owner = ''
        assigned_owner_display_name = ''
        
        # Extract CI sys_id properly (it might be a dict with display_value/value)
        ci_sys_id = ci.get('sys_id')
        if isinstance(ci_sys_id, dict):
            ci_sys_id = ci_sys_id.get('value', ci_sys_id.get('display_value', ''))
        
        if isinstance(assigned_to, dict):
            # ServiceNow returns expanded reference fields as objects
            # The assigned_to field has display_value (human name) and value (sys_id)
            assigned_owner_display_name = assigned_to.get('display_value', '')
            assigned_to_sys_id = assigned_to.get('value', '')
            
            # Try to get the username from expanded fields or look it up
            expanded_user_name = ci.get('assigned_to.user_name')
            if isinstance(expanded_user_name, dict):
                expanded_user_name = expanded_user_name.get('display_value', expanded_user_name.get('value', ''))
            
            assigned_owner = expanded_user_name or assigned_to.get('user_name', '')
            
            # If we don't have a username but have sys_id, look it up in user data
            if not assigned_owner and assigned_to_sys_id:
                user_record = user_by_sys_id.get(assigned_to_sys_id)
                if user_record:
                    assigned_owner = user_record.get('user_name', '')
                    # Use the display name from user record if we don't have one
                    if not assigned_owner_display_name:
                        assigned_owner_display_name = user_record.get('name', assigned_owner)
            
            # If still no username, use the sys_id as fallback
            if not assigned_owner:
                assigned_owner = assigned_to_sys_id
                        
        elif assigned_to:
            # If assigned_to is just a string (sys_id or username), look it up
            assigned_to_str = str(assigned_to)
            
            # First try to look up by sys_id, then by username
            user_record = user_by_sys_id.get(assigned_to_str) or user_by_name.get(assigned_to_str)
            if user_record:
                assigned_owner_display_name = user_record.get('name', assigned_to_str)
                assigned_owner = user_record.get('user_name', assigned_to_str)
            else:
                # If no user record found, assume it's a username and keep it as is
                assigned_owner = assigned_to_str
                assigned_owner_display_name = assigned_to_str
                
        if assigned_owner and ci_sys_id:
            labels_data.append({
                'ci_id': ci_sys_id,
                'assigned_owner': assigned_owner
            })
            # Store display name mapping - prefer the resolved display name
            final_display_name = assigned_owner_display_name or assigned_owner
            ci_owner_display_names[ci_sys_id] = final_display_name
            
            # Debug log for first few CIs
            if len(labels_data) <= 3:
                logger.info(f"CI {ci_sys_id}: assigned_owner='{assigned_owner}', display_name='{final_display_name}'")
            
    labels_df = pd.DataFrame(labels_data)
    
    logger.info(f"CIs with assigned owners: {len(labels_df)} out of {len(ci_data)}")
    if len(labels_df) > 0:
        logger.info(f"Sample assigned owner: {labels_df.iloc[0].to_dict()}")
    
    # Debug the ci_owner_display_names mapping
    logger.info(f"ci_owner_display_names mapping has {len(ci_owner_display_names)} entries")
    if ci_owner_display_names:
        # Show first few mappings
        sample_mappings = list(ci_owner_display_names.items())[:3]
        for ci_id, display_name in sample_mappings:
            logger.info(f"CI {ci_id} -> '{display_name}'")
    
    if len(labels_df) == 0:
        logger.warning("No CIs with assigned owners found")
        return []
    
    # Convert dates in audit data
    if len(audit_df) > 0:
        # Check if we have real audit data or converted string data
        if 'sys_created_on' in audit_df.columns:
            audit_df['sys_created_on'] = pd.to_datetime(audit_df['sys_created_on'], errors='coerce')
            logger.info(f"Audit records date range: {audit_df['sys_created_on'].min()} to {audit_df['sys_created_on'].max()}")
        else:
            logger.warning("Audit data appears to be converted from strings - missing expected columns")
            # Check if we have any converted string data
            converted_count = len(audit_df[audit_df['data_type'] == 'string_converted']) if 'data_type' in audit_df.columns else 0
            if converted_count > 0:
                logger.warning(f"Found {converted_count} audit records that were converted from strings")
    
    logger.info(f"Analyzing {len(labels_df)} CIs with assigned owners...")
    
    # Get stale CI list from model
    stale_ci_list = model.get_stale_ci_list(labels_df, audit_df, user_df, ci_df, ci_owner_display_names)
    
    logger.info(f"Found {len(stale_ci_list)} stale CIs")
    
    # If no stale CIs found, let's debug the first few CIs
    if len(stale_ci_list) == 0 and len(labels_df) > 0:
        logger.info("No stale CIs found. Debugging first CI...")
        first_ci = labels_df.iloc[0]
        ci_id = first_ci['ci_id']
        assigned_owner = first_ci['assigned_owner']
        
        # Get audit records for this CI
        ci_audit_records = audit_df[audit_df['documentkey'] == ci_id] if 'documentkey' in audit_df.columns else pd.DataFrame()
        logger.info(f"First CI {ci_id} has {len(ci_audit_records)} audit records")
        
        # Get user info
        user_info = user_df[user_df['user_name'] == assigned_owner].iloc[0].to_dict() if len(user_df[user_df['user_name'] == assigned_owner]) > 0 else {}
        logger.info(f"User info for {assigned_owner}: {user_info}")
        
        # Test model prediction manually
        ci_info = ci_df[ci_df['sys_id'] == ci_id].iloc[0].to_dict() if len(ci_df[ci_df['sys_id'] == ci_id]) > 0 else {}
        test_ci_data = {
            'ci_info': ci_info,
            'audit_records': ci_audit_records.to_dict('records'),
            'user_info': user_info,
            'assigned_owner': assigned_owner
        }
        
        test_result = model.predict_single(test_ci_data)
        logger.info(f"Test prediction for first CI: {test_result}")
    
    return stale_ci_list

def group_cis_by_recommended_owners(stale_ci_list):
    """
    Group stale CIs by their recommended owners for bulk assignment analysis
    """
    grouped = {}
    
    for ci in stale_ci_list:
        recommended_owners = ci.get('recommended_owners', [])
        
        # If CI has recommended owners, group by the top recommendation
        if recommended_owners and len(recommended_owners) > 0:
            top_recommendation = recommended_owners[0]  # Get the best recommendation
            username = top_recommendation.get('username', 'Unknown')
            
            if username not in grouped:
                grouped[username] = {
                    'recommended_owner': {
                        'username': username,
                        'display_name': top_recommendation.get('display_name', username),
                        'department': top_recommendation.get('department', 'Unknown'),
                        'avg_score': 0,
                        'total_activity_count': 0
                    },
                    'cis_to_assign': [],
                    'total_cis': 0,
                    'risk_breakdown': {
                        'Critical': 0,
                        'High': 0,
                        'Medium': 0,
                        'Low': 0
                    },
                    'avg_confidence': 0
                }
            
            # Add CI to this owner's group
            grouped[username]['cis_to_assign'].append({
                'ci_id': ci.get('ci_id'),
                'ci_name': ci.get('ci_name'),
                'ci_class': ci.get('ci_class'),
                'current_owner': ci.get('current_owner'),
                'confidence': ci.get('confidence'),
                'risk_level': ci.get('risk_level'),
                'staleness_reasons': ci.get('staleness_reasons', [])
            })
            
            # Update aggregated statistics
            grouped[username]['total_cis'] += 1
            grouped[username]['risk_breakdown'][ci.get('risk_level', 'Low')] += 1
            
            # Update averages
            current_total = grouped[username]['total_cis']
            current_avg_confidence = grouped[username]['avg_confidence']
            grouped[username]['avg_confidence'] = (
                (current_avg_confidence * (current_total - 1) + ci.get('confidence', 0)) / current_total
            )
            
            # Update owner stats
            current_avg_score = grouped[username]['recommended_owner']['avg_score']
            grouped[username]['recommended_owner']['avg_score'] = (
                (current_avg_score * (current_total - 1) + top_recommendation.get('score', 0)) / current_total
            )
            grouped[username]['recommended_owner']['total_activity_count'] += top_recommendation.get('activity_count', 0)
        
        else:
            # Handle CIs with no recommendations
            if 'No Recommendation' not in grouped:
                grouped['No Recommendation'] = {
                    'recommended_owner': {
                        'username': 'No Recommendation',
                        'display_name': 'No Suitable Owner Found',
                        'department': 'Manual Review Required',
                        'avg_score': 0,
                        'total_activity_count': 0
                    },
                    'cis_to_assign': [],
                    'total_cis': 0,
                    'risk_breakdown': {
                        'Critical': 0,
                        'High': 0,
                        'Medium': 0,
                        'Low': 0
                    },
                    'avg_confidence': 0
                }
            
            grouped['No Recommendation']['cis_to_assign'].append({
                'ci_id': ci.get('ci_id'),
                'ci_name': ci.get('ci_name'),
                'ci_class': ci.get('ci_class'),
                'current_owner': ci.get('current_owner'),
                'confidence': ci.get('confidence'),
                'risk_level': ci.get('risk_level'),
                'staleness_reasons': ci.get('staleness_reasons', [])
            })
            
            grouped['No Recommendation']['total_cis'] += 1
            grouped['No Recommendation']['risk_breakdown'][ci.get('risk_level', 'Low')] += 1
            
            current_total = grouped['No Recommendation']['total_cis']
            current_avg_confidence = grouped['No Recommendation']['avg_confidence']
            grouped['No Recommendation']['avg_confidence'] = (
                (current_avg_confidence * (current_total - 1) + ci.get('confidence', 0)) / current_total
            )
    
    # Convert to list and sort by total CIs (most CIs first)
    grouped_list = []
    for username, data in grouped.items():
        # Round averages for cleaner display
        data['avg_confidence'] = round(data['avg_confidence'], 2)
        data['recommended_owner']['avg_score'] = round(data['recommended_owner']['avg_score'], 1)
        
        grouped_list.append({
            'username': username,
            **data
        })
    
    # Sort by total CIs descending (owners with most CIs first)
    grouped_list.sort(key=lambda x: x['total_cis'], reverse=True)
    
    return grouped_list

@app.route('/reload-model', methods=['POST'])
def reload_model():
    """Reload the ML model"""
    try:
        global model
        with open('staleness_detector_model.pkl', 'rb') as f:
            model = pickle.load(f)
        return jsonify({'success': True, 'message': 'Model reloaded successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/assign-ci-owner', methods=['POST'])
def assign_ci_owner():
    """Assign a CI to a new owner by updating the assigned_to field"""
    session = create_session()
    try:
        data = request.get_json()
        instance_url = data.get('instance_url')
        username = data.get('username')
        password = data.get('password')
        ci_id = data.get('ci_id')
        new_owner_username = data.get('new_owner_username')
        
        if not all([instance_url, username, password, ci_id, new_owner_username]):
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # First, get the current owner information with expanded reference fields
        ci_url = f"{instance_url}/api/now/table/cmdb_ci/{ci_id}"
        try:
            ci_response = session.get(
                ci_url,
                auth=(username, password),
                headers={'Accept': 'application/json'},
                params={
                    'sysparm_fields': 'assigned_to,name,sys_class_name,assigned_to.user_name,assigned_to.name',
                    'sysparm_display_value': 'all'  # Get both display values and actual values
                },
                timeout=(30, 90)  # (connect timeout, read timeout)
            )
            
            if ci_response.status_code != 200:
                error_msg = f"Failed to fetch CI information: HTTP {ci_response.status_code}"
                logger.error(error_msg)
                return jsonify({'error': error_msg}), 500
                
            ci_data = ci_response.json().get('result', {})
            
            # Extract current owner information
            current_owner_info = ci_data.get('assigned_to', {})
            if isinstance(current_owner_info, dict):
                current_owner = {
                    'display_name': current_owner_info.get('display_value', 'Unknown'),
                    'sys_id': current_owner_info.get('value', ''),
                    'username': ci_data.get('assigned_to.user_name', {}).get('display_value', '')
                }
            else:
                current_owner = {
                    'display_name': 'Unknown',
                    'sys_id': '',
                    'username': ''
                }
            
            ci_name = ci_data.get('name', {}).get('display_value', 'Unknown')
            ci_class = ci_data.get('sys_class_name', {}).get('display_value', 'Unknown')
            
        except requests.exceptions.Timeout:
            error_msg = "Timeout while fetching CI information. Please try again."
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 504
        except requests.exceptions.RequestException as e:
            error_msg = f"Error fetching CI information: {str(e)}"
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 500
        
        # Get the new owner's information
        user_url = f"{instance_url}/api/now/table/sys_user"
        try:
            user_response = session.get(
                user_url,
                auth=(username, password),
                headers={'Accept': 'application/json'},
                params={
                    'sysparm_query': f'user_name={new_owner_username}',
                    'sysparm_fields': 'sys_id,user_name,name',
                    'sysparm_limit': 1
                },
                timeout=(30, 90)
            )
            
            if user_response.status_code != 200:
                error_msg = f"Failed to find user in ServiceNow: HTTP {user_response.status_code}"
                logger.error(error_msg)
                return jsonify({'error': error_msg}), 500
            
            user_data = user_response.json().get('result', [])
            if not user_data:
                error_msg = f"User {new_owner_username} not found in ServiceNow"
                logger.error(error_msg)
                return jsonify({'error': error_msg}), 404
            
            user_sys_id = user_data[0].get('sys_id')
            user_display_name = user_data[0].get('name', new_owner_username)
            
        except requests.exceptions.Timeout:
            error_msg = "Timeout while fetching user information. Please try again."
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 504
        except requests.exceptions.RequestException as e:
            error_msg = f"Error fetching user information: {str(e)}"
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 500
        
        # Update the CI's assigned_to field
        try:
            update_data = {
                'assigned_to': user_sys_id  # Use sys_id for assignment
            }
            
            update_response = session.patch(
                ci_url,
                auth=(username, password),
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                json=update_data,
                timeout=(30, 90)
            )
            
            if update_response.status_code == 200:
                # Store the assignment in history with complete owner information
                assignment_record = {
                    'id': len(assignment_history),
                    'timestamp': datetime.now().isoformat(),
                    'ci_id': ci_id,
                    'ci_name': ci_name,
                    'ci_class': ci_class,
                    'previous_owner': {
                        'display_name': current_owner['display_name'],
                        'sys_id': current_owner['sys_id'],
                        'username': current_owner['username']
                    },
                    'new_owner': {
                        'username': new_owner_username,
                        'display_name': user_display_name,
                        'sys_id': user_sys_id
                    },
                    'instance_url': instance_url
                }
                assignment_history.append(assignment_record)
                
                logger.info(f"Successfully assigned CI {ci_id} to user {user_display_name}")
                return jsonify({
                    'success': True,
                    'message': f'CI successfully assigned to {user_display_name}',
                    'new_owner': {
                        'username': new_owner_username,
                        'display_name': user_display_name,
                        'sys_id': user_sys_id
                    },
                    'assignment_id': assignment_record['id']
                })
            else:
                error_msg = f"Failed to update CI assignment: HTTP {update_response.status_code}"
                logger.error(error_msg)
                return jsonify({'error': error_msg}), 500
                
        except requests.exceptions.Timeout:
            error_msg = "Timeout while updating CI assignment. Please try again."
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 504
        except requests.exceptions.RequestException as e:
            error_msg = f"Error updating CI assignment: {str(e)}"
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 500
            
    except Exception as e:
        error_msg = f"Unexpected error in assign_ci_owner: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return jsonify({'error': error_msg}), 500
    finally:
        session.close()

@app.route('/assignment-history', methods=['GET'])
def get_assignment_history():
    """Get the history of CI assignments"""
    try:
        # Return the full history, sorted by timestamp descending (newest first)
        sorted_history = sorted(assignment_history, key=lambda x: x['timestamp'], reverse=True)
        return jsonify({
            'success': True,
            'history': sorted_history
        })
    except Exception as e:
        logger.error(f"Error fetching assignment history: {str(e)}", exc_info=True)
        return jsonify({'error': f'Failed to fetch history: {str(e)}'}), 500

@app.route('/undo-assignment', methods=['POST'])
def undo_assignment():
    """Undo a CI assignment by reverting to the previous owner"""
    session = create_session()
    try:
        data = request.get_json()
        instance_url = data.get('instance_url', '').rstrip('/')  # Normalize URL by removing trailing slash
        username = data.get('username')
        password = data.get('password')
        assignment_id = data.get('assignment_id')
        
        logger.info(f"Received undo request for assignment ID: {assignment_id}")
        
        if not all([instance_url, username, password, assignment_id is not None]):
            missing_params = [k for k, v in {'instance_url': instance_url, 'username': username, 
                                           'password': password, 'assignment_id': assignment_id}.items() if v is None]
            error_msg = f"Missing required parameters: {', '.join(missing_params)}"
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 400
            
        # Convert assignment_id to int if it's not already
        try:
            assignment_id = int(assignment_id)
        except (TypeError, ValueError):
            error_msg = f"Invalid assignment ID format: {assignment_id}"
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 400
            
        # Find the assignment record
        assignment = next((a for a in assignment_history if a['id'] == assignment_id), None)
        if not assignment:
            logger.error(f"Assignment ID {assignment_id} not found in history")
            return jsonify({'error': 'Assignment record not found'}), 404
            
        logger.info(f"Found assignment record for CI: {assignment['ci_name']}")
        
        # First verify the current state of the CI
        ci_url = f"{instance_url}/api/now/table/cmdb_ci/{assignment['ci_id']}"
        try:
            # Get current CI state
            ci_response = session.get(
                ci_url,
                auth=(username, password),
                headers={'Accept': 'application/json'},
                params={
                    'sysparm_fields': 'assigned_to,name,sys_class_name,assigned_to.user_name,assigned_to.name',
                    'sysparm_display_value': 'all'
                },
                timeout=(30, 90)
            )
            
            if ci_response.status_code != 200:
                error_msg = f"Failed to fetch current CI state: HTTP {ci_response.status_code}"
                logger.error(error_msg)
                return jsonify({'error': error_msg}), 500
                
            # Verify we can revert
            if not assignment['previous_owner'].get('sys_id'):
                logger.error("Previous owner sys_id is missing")
                return jsonify({'error': 'Cannot undo: previous owner information is incomplete'}), 400
                
            # Prepare the update data
            update_data = {
                'assigned_to': assignment['previous_owner']['sys_id']
            }
            
            # Attempt to update the CI
            update_response = session.patch(
                ci_url,
                auth=(username, password),
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                json=update_data,
                timeout=(30, 90)
            )
            
            if update_response.status_code == 200:
                # Verify the update was successful
                verify_response = session.get(
                    ci_url,
                    auth=(username, password),
                    headers={'Accept': 'application/json'},
                    params={
                        'sysparm_fields': 'assigned_to,name,sys_class_name,assigned_to.user_name,assigned_to.name',
                        'sysparm_display_value': 'all'
                    },
                    timeout=(30, 90)
                )
                
                if verify_response.status_code == 200:
                    # Add a new history record for the undo operation
                    undo_record = {
                        'id': len(assignment_history),
                        'timestamp': datetime.now().isoformat(),
                        'ci_id': assignment['ci_id'],
                        'ci_name': assignment['ci_name'],
                        'ci_class': assignment['ci_class'],
                        'previous_owner': assignment['new_owner'],
                        'new_owner': assignment['previous_owner'],
                        'instance_url': instance_url,
                        'is_undo': True,
                        'undoes_assignment_id': assignment_id
                    }
                    assignment_history.append(undo_record)
                    
                    return jsonify({
                        'success': True,
                        'message': f'Successfully reverted CI assignment to {assignment["previous_owner"]["display_name"]}',
                        'assignment_id': undo_record['id']
                    })
                else:
                    error_msg = "Failed to verify the undo operation"
                    logger.error(error_msg)
                    return jsonify({'error': error_msg}), 500
            else:
                error_msg = f"Failed to revert CI assignment: HTTP {update_response.status_code}"
                logger.error(error_msg)
                return jsonify({'error': error_msg}), 500
                
        except requests.exceptions.Timeout:
            error_msg = "Timeout while reverting CI assignment. Please try again."
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 504
        except requests.exceptions.RequestException as e:
            error_msg = f"Error reverting CI assignment: {str(e)}"
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 500
            
    except Exception as e:
        error_msg = f"Unexpected error in undo_assignment: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return jsonify({'error': error_msg}), 500
    finally:
        session.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
import pandas as pd
import numpy as np
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

class RuleBasedStalenessDetector:
    """
    Pickle-serializable version of the staleness detector
    """

    def __init__(self):
        self.rules = self._define_detection_rules()
        self.scenario_patterns = self._define_scenario_patterns()

    def _define_detection_rules(self):
        """Define rules based on the document patterns"""
        return {
            'inactive_owner_active_others': {
                'description': 'Owner has 0 activities while others are active',
                'conditions': [
                    'owner_activity_count == 0',
                    'total_activity_count >= 2',
                    'other_users_count > 0'
                ],
                'confidence': 0.95,
                'scenarios': ['1', '5', '11']
            },
            'account_terminated': {
                'description': 'Owner account is inactive/terminated',
                'conditions': [
                    'owner_active == False'
                ],
                'confidence': 1.0,
                'scenarios': ['5', '8']
            },
            'vendor_account': {
                'description': 'Assigned to vendor/external account',
                'conditions': [
                    "'vendor' in owner_name.lower() or 'external' in owner_name.lower() or '.contractor' in owner_name"
                ],
                'confidence': 0.85,
                'scenarios': ['4', '8']
            },
            'generic_account': {
                'description': 'Assigned to generic account',
                'conditions': [
                    "'.generic' in owner_name or 'admin.generic' in owner_name or 'team.generic' in owner_name"
                ],
                'confidence': 0.9,
                'scenarios': ['7', '10', '15']
            },
            'extended_inactivity': {
                'description': 'No owner activity for 150+ days',
                'conditions': [
                    'days_since_owner_activity > 150',
                    'recent_other_activities >= 0'
                ],
                'confidence': 0.85,
                'scenarios': ['1', '9']
            },
            'role_transition': {
                'description': 'User role changed significantly',
                'conditions': [
                    'owner_role_changes > 0',
                    'owner_title_changed == True'
                ],
                'confidence': 0.75,
                'scenarios': ['1', '3', '9', '11']
            },
            'department_transition': {
                'description': 'User moved to different department',
                'conditions': [
                    'owner_dept_changed == True',
                    'days_since_owner_activity > 15'
                ],
                'confidence': 0.8,
                'scenarios': ['3', '6']
            },
            'group_disbanded': {
                'description': 'Assigned group no longer active',
                'conditions': [
                    'assigned_group_active == False'
                ],
                'confidence': 0.9,
                'scenarios': ['6', '13']
            },
            'dominant_other_user': {
                'description': 'Another user has majority of recent activities',
                'conditions': [
                    'top_other_user_ratio > 0.5',
                    'owner_activity_ratio < 0.3'
                ],
                'confidence': 0.85,
                'scenarios': ['2', '7', '12']
            },
            'ownership_field_changes': {
                'description': 'Ownership fields modified by non-owner',
                'conditions': [
                    'non_owner_ownership_changes > 0'
                ],
                'confidence': 0.9,
                'scenarios': ['multiple']
            },
            'minimal_owner_activity': {
                'description': 'Owner has very little recent activity',
                'conditions': [
                    'owner_activity_count <= 1',
                    'total_activity_count > 0'
                ],
                'confidence': 0.7,
                'scenarios': ['general']
            },
            # New enhanced rules using title and department change tracking
            'owner_title_changed_inactive': {
                'description': 'Owner title changed but became inactive on CI',
                'conditions': [
                    'owner_profile_changes_count > 0',
                    'owner_title_changed == True',
                    'owner_activity_count == 0',
                    'days_since_owner_activity > 30'
                ],
                'confidence': 0.9,
                'scenarios': ['1', '3', '9']
            },
            'owner_department_changed_inactive': {
                'description': 'Owner department changed and became inactive',
                'conditions': [
                    'owner_profile_changes_count > 0',
                    'owner_dept_changed == True',
                    'owner_activity_count <= 1',
                    'days_since_owner_activity > 30'
                ],
                'confidence': 0.85,
                'scenarios': ['3', '6']
            },
            'multiple_profile_changes_inactive': {
                'description': 'Owner had multiple profile changes and became inactive',
                'conditions': [
                    'owner_profile_changes_count >= 2',
                    'owner_activity_count == 0',
                    'recent_other_activities > 0'
                ],
                'confidence': 0.9,
                'scenarios': ['1', '3', '9', '11']
            },
            'ci_users_role_transitions': {
                'description': 'Multiple users associated with CI had role transitions',
                'conditions': [
                    'title_changes_count >= 2',
                    'owner_activity_ratio < 0.4'
                ],
                'confidence': 0.8,
                'scenarios': ['3', '6', '13']
            }
        }

    def _define_scenario_patterns(self):
        """Define specific patterns from each scenario"""
        return {
            'promotion_pattern': {
                'indicators': [
                    'title_change',
                    'role_additions',
                    'group_membership_change',
                    'increased_activity_by_new_person',
                    'zero_activity_by_old_owner'
                ],
                'scenarios': ['1', '23']
            },
            'onboarding_mismatch': {
                'indicators': [
                    'new_user_created',
                    'assigned_to_manager',
                    'actual_user_different',
                    'daily_activities_by_actual_user'
                ],
                'scenarios': ['2', '9']
            },
            'reorganization': {
                'indicators': [
                    'new_group_created',
                    'old_group_deactivated',
                    'mass_user_transitions',
                    'department_changes'
                ],
                'scenarios': ['3', '6', '13']
            },
            'external_to_internal': {
                'indicators': [
                    'contractor_account_deactivated',
                    'new_internal_account_created',
                    'vendor_prefix_in_old_account',
                    'enhanced_permissions'
                ],
                'scenarios': ['4', '8']
            }
        }

    def predict_single(self, ci_data: Dict) -> Dict:
        """
        Predict staleness for a single CI
        Input format expected from ServiceNow data
        """
        try:
            # Extract features from ServiceNow data
            features = self._extract_features_from_servicenow_data(ci_data)
            
            # Get recommendation for new owner FIRST
            new_owner_recommendation = self._recommend_new_owner_from_data(ci_data)
            
            # Now do a second pass to check profile changes for recommended owners
            if new_owner_recommendation and ci_data.get('all_user_audit_records'):
                recommended_sys_ids = set()
                for rec in (new_owner_recommendation if isinstance(new_owner_recommendation, list) else [new_owner_recommendation]):
                    if rec.get('user_sys_id'):
                        recommended_sys_ids.add(rec.get('user_sys_id'))
                
                if recommended_sys_ids:
                    # Check if any recommended owners have profile changes
                    for record in ci_data.get('all_user_audit_records', []):
                        documentkey = record.get('documentkey', '')
                        if documentkey in recommended_sys_ids:
                            fieldname = record.get('fieldname', '')
                            if fieldname in ['title', 'department']:
                                # Add to features if not already counted
                                print(f"DEBUG: Found profile change for recommended owner - field: {fieldname}, sys_id: {documentkey}")
            
            # Apply rules
            triggered_rules = []
            total_confidence = 0

            for rule_name, rule_def in self.rules.items():
                if self._evaluate_rule(features, rule_def['conditions']):
                    triggered_rules.append({
                        'rule': rule_name,
                        'description': rule_def['description'],
                        'confidence': rule_def['confidence'],
                        'scenarios': rule_def['scenarios']
                    })
                    total_confidence = max(total_confidence, rule_def['confidence'])

            # Add specific title/department change reasons with details
            if features.get('owner_profile_changes_details'):
                for change in features['owner_profile_changes_details']:
                    if change['field'] == 'title':
                        triggered_rules.append({
                            'rule': 'owner_title_change_detected',
                            'description': f"Owner's title changed from '{change['old_value']}' to '{change['new_value']}' on {change['change_date']}",
                            'confidence': 0.85,
                            'scenarios': ['profile_change']
                        })
                        total_confidence = max(total_confidence, 0.85)
                    elif change['field'] == 'department':
                        triggered_rules.append({
                            'rule': 'owner_department_change_detected',
                            'description': f"Owner's department changed from '{change['old_value']}' to '{change['new_value']}' on {change['change_date']}",
                            'confidence': 0.85,
                            'scenarios': ['profile_change']
                        })
                        total_confidence = max(total_confidence, 0.85)
            
            # Add reasons for other users' changes if significant
            if features.get('title_changes_count', 0) > 0 and features.get('owner_activity_count', 0) == 0:
                title_changes = features.get('title_changes_details', [])
                non_owner_changes = [c for c in title_changes if not c.get('is_owner', False)]
                if non_owner_changes:
                    triggered_rules.append({
                        'rule': 'ci_users_title_changes',
                        'description': f"{len(non_owner_changes)} user(s) who work on this CI had title changes while owner remained inactive",
                        'confidence': 0.75,
                        'scenarios': ['team_transition']
                    })
                    total_confidence = max(total_confidence, 0.75)
            
            if features.get('department_changes_count', 0) > 0 and features.get('owner_activity_count', 0) == 0:
                dept_changes = features.get('department_changes_details', [])
                non_owner_changes = [c for c in dept_changes if not c.get('is_owner', False)]
                if non_owner_changes:
                    triggered_rules.append({
                        'rule': 'ci_users_department_changes',
                        'description': f"{len(non_owner_changes)} user(s) who work on this CI had department changes while owner remained inactive",
                        'confidence': 0.75,
                        'scenarios': ['team_transition']
                    })
                    total_confidence = max(total_confidence, 0.75)

            # Determine staleness
            is_stale = total_confidence > 0.7

            return {
                'is_stale': is_stale,
                'confidence': total_confidence,
                'triggered_rules': triggered_rules,
                'new_owner_recommendation': new_owner_recommendation,
                'features': features
            }

        except Exception as e:
            return {
                'is_stale': False,
                'confidence': 0.0,
                'triggered_rules': [],
                'new_owner_recommendation': None,
                'error': str(e)
            }

    def _extract_features_from_servicenow_data(self, ci_data: Dict) -> Dict:
        """
        Extract features from ServiceNow data format
        Expected input structure:
        {
            'ci_info': {...},
            'audit_records': [...],
            'user_info': {...},
            'assigned_owner': '...',
            'user_data_context': {...},
            'all_user_audit_records': [...] # All user profile audit records
        }
        """
        features = {}
        
        # Basic info
        assigned_owner = ci_data.get('assigned_owner', '')
        features['owner_name'] = assigned_owner
        
        # Get current owner's sys_id
        user_info = ci_data.get('user_info', {})
        owner_sys_id = user_info.get('sys_id', '')
        
        # Also try to get owner sys_id from CI info if not in user_info
        if not owner_sys_id:
            ci_info = ci_data.get('ci_info', {})
            assigned_to_field = ci_info.get('assigned_to', {})
            if isinstance(assigned_to_field, dict):
                owner_sys_id = assigned_to_field.get('value', '')
            # Check expanded field
            if not owner_sys_id:
                owner_sys_id = ci_info.get('assigned_to.sys_id', {})
                if isinstance(owner_sys_id, dict):
                    owner_sys_id = owner_sys_id.get('value', owner_sys_id.get('display_value', ''))
        
        # Debug logging
        if owner_sys_id:
            print(f"DEBUG: Owner '{assigned_owner}' has sys_id: {owner_sys_id}")
        
        # Get all user profile audit records
        all_user_audit_records = ci_data.get('all_user_audit_records', [])
        
        # Get user lookup data
        user_by_sys_id = ci_data.get('user_by_sys_id', {})
        
        # Audit records analysis
        audit_records = ci_data.get('audit_records', [])
        features['total_activity_count'] = len(audit_records)
        
        # Separate CI audit records from user profile audit records
        ci_audit_records = [r for r in audit_records if r.get('audit_type') != 'user_profile_change']
        
        # Owner activity analysis (only CI-related activities)
        # Handle cases where audit records contain sys_ids instead of usernames
        owner_activities = []
        for record in ci_audit_records:
            audit_user = record.get('user', '')
            # Direct username match
            if audit_user == assigned_owner:
                owner_activities.append(record)
            # Check if audit_user is a sys_id that matches the owner's sys_id
            elif audit_user == owner_sys_id:
                owner_activities.append(record)
            # Check if audit_user is a sys_id that can be resolved to the assigned_owner username
            elif audit_user in user_by_sys_id:
                resolved_user = user_by_sys_id[audit_user]
                if resolved_user.get('user_name') == assigned_owner:
                    owner_activities.append(record)
        
        features['owner_activity_count'] = len(owner_activities)
        
        # Debug logging for owner activity mismatch
        if len(ci_audit_records) > 0:
            print(f"DEBUG: CI {ci_data.get('ci_id', 'unknown')} - assigned_owner: '{assigned_owner}', owner_sys_id: '{owner_sys_id}'")
            print(f"DEBUG: Total CI audit records: {len(ci_audit_records)}")
            print(f"DEBUG: Owner activities found: {len(owner_activities)}")
            if len(ci_audit_records) > 0:
                unique_users = set(r.get('user', '') for r in ci_audit_records)
                print(f"DEBUG: Unique users in audit records: {list(unique_users)[:10]}")
                # Check if any audit users can be resolved to the assigned owner
                for user in unique_users:
                    if user == assigned_owner:
                        print(f"DEBUG: Direct username match - assigned_owner: '{assigned_owner}', audit_user: '{user}'")
                    elif user == owner_sys_id:
                        print(f"DEBUG: Sys_id match - owner_sys_id: '{owner_sys_id}', audit_user: '{user}'")
                    elif user in user_by_sys_id and user_by_sys_id[user].get('user_name') == assigned_owner:
                        print(f"DEBUG: Resolved sys_id match - assigned_owner: '{assigned_owner}', audit_user: '{user}' -> '{user_by_sys_id[user].get('user_name')}'")
            if len(owner_activities) == 0 and len(ci_audit_records) > 0:
                print(f"DEBUG: WARNING - No owner activities found but CI has {len(ci_audit_records)} audit records!")
        
        if len(ci_audit_records) > 0:
            features['owner_activity_ratio'] = len(owner_activities) / len(ci_audit_records)
        else:
            features['owner_activity_ratio'] = 0

        # Days since owner activity
        if owner_activities:
            try:
                last_activity = max([self._parse_date(r.get('sys_created_on', '')) for r in owner_activities])
                features['days_since_owner_activity'] = (datetime.now() - last_activity).days
            except:
                features['days_since_owner_activity'] = 999
        else:
            features['days_since_owner_activity'] = 999

        # Other users analysis (only CI-related activities)
        other_users = {}
        for record in ci_audit_records:
            user = record.get('user', '')
            if user != assigned_owner and user:
                other_users[user] = other_users.get(user, 0) + 1

        features['other_users_count'] = len(other_users)
        
        if other_users:
            top_user = max(other_users.items(), key=lambda x: x[1])
            features['top_other_user'] = top_user[0]
            features['top_other_user_count'] = top_user[1]
            features['top_other_user_ratio'] = top_user[1] / len(ci_audit_records)
        else:
            features['top_other_user'] = None
            features['top_other_user_count'] = 0
            features['top_other_user_ratio'] = 0

        # Recent activity (last 30 days) - only CI-related
        recent_cutoff = datetime.now() - timedelta(days=30)
        recent_other_activities = 0
        for record in ci_audit_records:
            if record.get('user') != assigned_owner:
                try:
                    record_date = self._parse_date(record.get('sys_created_on', ''))
                    if record_date > recent_cutoff:
                        recent_other_activities += 1
                except:
                    pass
        features['recent_other_activities'] = recent_other_activities

        # User info analysis
        features['owner_active'] = user_info.get('active', True)

        # Enhanced role and department change analysis
        # Get user data context for better analysis
        user_data_context = ci_data.get('user_data_context', {})
        user_by_sys_id = ci_data.get('user_by_sys_id', {})
        
        # Track title and department changes for all users associated with this CI
        title_changes = []
        department_changes = []
        owner_profile_changes = []
        
        # Get all users who have interacted with this CI (including recommended owners)
        ci_related_users = set()
        ci_related_user_sys_ids = set()
        
        # Add current owner
        if assigned_owner and owner_sys_id:
            ci_related_users.add(assigned_owner)
            ci_related_user_sys_ids.add(owner_sys_id)
        
        # Add users who modified the CI
        for record in ci_audit_records:
            user = record.get('user', '')
            if user and user in user_data_context:
                ci_related_users.add(user)
                user_sys_id = user_data_context[user].get('sys_id', '')
                if user_sys_id:
                    ci_related_user_sys_ids.add(user_sys_id)
        
        # Add recommended owners if available
        new_owner_recommendation = ci_data.get('new_owner_recommendation')
        if new_owner_recommendation:
            if isinstance(new_owner_recommendation, dict):
                rec_user = new_owner_recommendation.get('user', '')
                if rec_user and rec_user in user_data_context:
                    ci_related_users.add(rec_user)
                    rec_sys_id = user_data_context[rec_user].get('sys_id', '')
                    if rec_sys_id:
                        ci_related_user_sys_ids.add(rec_sys_id)
            elif isinstance(new_owner_recommendation, list):
                for rec in new_owner_recommendation:
                    rec_user = rec.get('user', '')
                    if rec_user and rec_user in user_data_context:
                        ci_related_users.add(rec_user)
                        rec_sys_id = user_data_context[rec_user].get('sys_id', '')
                        if rec_sys_id:
                            ci_related_user_sys_ids.add(rec_sys_id)
        
        # Now look for user profile changes using user sys_ids as documentkey
        for record in all_user_audit_records:
            documentkey = record.get('documentkey', '')  # This is the user's sys_id for profile changes
            fieldname = record.get('fieldname', '')
            oldvalue = record.get('oldvalue', '')
            newvalue = record.get('newvalue', '')
            change_date = record.get('sys_created_on', '')
            
            # Check if this documentkey matches any of our CI-related users
            if documentkey in ci_related_user_sys_ids:
                # Find which user this sys_id belongs to
                user_for_sys_id = None
                for username, user_data in user_data_context.items():
                    if user_data.get('sys_id') == documentkey:
                        user_for_sys_id = username
                        break
                
                if user_for_sys_id:
                    change_info = {
                        'user': user_for_sys_id,
                        'user_sys_id': documentkey,
                        'field': fieldname,
                        'old_value': oldvalue,
                        'new_value': newvalue,
                        'change_date': change_date,
                        'is_owner': user_for_sys_id == assigned_owner
                    }
                    
                    # Categorize profile changes
                    if fieldname in ['title', 'job_title', 'u_job_title']:
                        title_changes.append(change_info)
                        if user_for_sys_id == assigned_owner:
                            owner_profile_changes.append(change_info)
                    elif fieldname in ['department', 'cost_center', 'location', 'company']:
                        department_changes.append(change_info)
                        if user_for_sys_id == assigned_owner:
                            owner_profile_changes.append(change_info)
                    elif fieldname in ['manager', 'active', 'locked_out', 'u_employee_type', 'u_vendor_status']:
                        # These are also significant profile changes
                        if user_for_sys_id == assigned_owner:
                            owner_profile_changes.append(change_info)
        
        # Debug logging for profile changes
        if len(title_changes) > 0 or len(department_changes) > 0:
            print(f"DEBUG: Found profile changes for CI - Title: {len(title_changes)}, Dept: {len(department_changes)}, Owner: {len(owner_profile_changes)}")
            if owner_sys_id:
                print(f"DEBUG: Owner sys_id: {owner_sys_id}, Owner username: {assigned_owner}")
            print(f"DEBUG: CI-related user sys_ids: {list(ci_related_user_sys_ids)[:5]}...")  # Show first 5
        
        # Enhanced features for title and department changes
        features['title_changes_count'] = len(title_changes)
        features['department_changes_count'] = len(department_changes)
        features['owner_profile_changes_count'] = len(owner_profile_changes)
        
        # Detailed change information
        features['title_changes_details'] = title_changes
        features['department_changes_details'] = department_changes
        features['owner_profile_changes_details'] = owner_profile_changes
        
        # Original role and department analysis (for backward compatibility)
        role_change_fields = ['title', 'role', 'department']
        role_changes = sum(1 for r in ci_audit_records 
                          if r.get('fieldname') in role_change_fields and r.get('user') == assigned_owner)
        features['owner_role_changes'] = role_changes
        features['owner_title_changed'] = len([c for c in owner_profile_changes if c['field'] == 'title']) > 0
        features['owner_dept_changed'] = len([c for c in owner_profile_changes if c['field'] == 'department']) > 0

        # Group status (simplified)
        features['assigned_group_active'] = True  # Default assumption

        # Ownership field changes by non-owner
        ownership_fields = ['assigned_to', 'managed_by', 'support_group']
        ownership_changes = sum(1 for r in ci_audit_records 
                              if r.get('fieldname') in ownership_fields and r.get('user') != assigned_owner)
        features['non_owner_ownership_changes'] = ownership_changes

        return features

    def _parse_date(self, date_str: str) -> datetime:
        """Parse ServiceNow date format"""
        try:
            # Try common ServiceNow date formats
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d',
                '%m/%d/%Y %H:%M:%S',
                '%m/%d/%Y'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
            
            # If all formats fail, return a very old date
            return datetime(1900, 1, 1)
        except:
            return datetime(1900, 1, 1)

    def _clean_department_field(self, dept_field):
        """Clean department field to remove ServiceNow link information"""
        if not dept_field:
            return 'Unknown'
        
        # If it's a simple string, return as is
        if isinstance(dept_field, str) and not dept_field.startswith('{') and 'link' not in dept_field.lower():
            return dept_field
        
        # If it's a dict (ServiceNow reference field), extract display_value
        if isinstance(dept_field, dict):
            return dept_field.get('display_value', dept_field.get('value', 'Unknown'))
        
        # If it's a string that looks like a dict/JSON or contains link info, clean it up
        if isinstance(dept_field, str) and (dept_field.startswith('{') or 'link' in dept_field.lower()):
            try:
                import json
                if dept_field.startswith('{'):
                    dept_data = json.loads(dept_field)
                    return dept_data.get('display_value', dept_data.get('value', 'Unknown'))
                else:
                    # If it contains link info but isn't JSON, just return "Unknown"
                    return 'Unknown'
            except:
                return 'Unknown'
        
        # Default fallback
        return str(dept_field) if dept_field else 'Unknown'

    def _evaluate_rule(self, features: Dict, conditions: List[str]) -> bool:
        """Evaluate if all conditions are met"""
        for condition in conditions:
            try:
                # Create local variables for evaluation
                local_vars = features.copy()
                
                # Evaluate condition
                if not eval(condition, {"__builtins__": {}}, local_vars):
                    return False
            except:
                return False
        return True

    def _recommend_new_owner_from_data(self, ci_data: Dict) -> Optional[Dict]:
        """Recommend new owner based on ServiceNow data"""
        try:
            audit_records = ci_data.get('audit_records', [])
            assigned_owner = ci_data.get('assigned_owner', '')
            username_to_display_name = ci_data.get('username_to_display_name', {})
            user_data_context = ci_data.get('user_data_context', {})
            
            # Get user data for department lookup
            user_info_lookup = {}
            if 'user_info' in ci_data:
                # This is the user info for the assigned owner, but we need all users
                pass
            
            # Build user lookup from audit records and try to match with user data
            # We'll need to get user data from the broader context
            
            if not audit_records:
                return None

            # Analyze user activities
            user_activities = {}
            for record in audit_records:
                user = record.get('user', '')
                if user and user != assigned_owner:
                    if user not in user_activities:
                        user_activities[user] = {
                            'count': 0,
                            'last_activity': None,
                            'first_activity': None,
                            'fields': set()
                        }
                    
                    user_activities[user]['count'] += 1
                    user_activities[user]['fields'].add(record.get('fieldname', ''))
                    
                    try:
                        record_date = self._parse_date(record.get('sys_created_on', ''))
                        
                        if user_activities[user]['last_activity'] is None or record_date > user_activities[user]['last_activity']:
                            user_activities[user]['last_activity'] = record_date
                        
                        if user_activities[user]['first_activity'] is None or record_date < user_activities[user]['first_activity']:
                            user_activities[user]['first_activity'] = record_date
                    except:
                        pass

            if not user_activities:
                return None

            # Score users based on activity
            user_scores = []
            for user, activity in user_activities.items():
                score = 0
                
                # Activity count (more activities = higher score)
                score += min(activity['count'] * 10, 50)  # Cap at 50 points
                
                # Recency (recent activity = higher score)
                if activity['last_activity']:
                    days_since_last = (datetime.now() - activity['last_activity']).days
                    if days_since_last < 30:
                        score += 25
                    elif days_since_last < 90:
                        score += 15
                    elif days_since_last < 180:
                        score += 5
                
                # Ownership-related changes
                ownership_fields = {'assigned_to', 'managed_by', 'support_group', 'owned_by'}
                ownership_changes = len(activity['fields'].intersection(ownership_fields))
                score += ownership_changes * 5
                
                # Get user details including sys_id
                user_details = user_data_context.get(user, {})
                user_sys_id = user_details.get('sys_id', '')
                
                # Resolve display name: try username mapping first, then sys_id lookup, then fallback
                display_name = username_to_display_name.get(user)  # Try username mapping
                if not display_name:
                    # If user is a sys_id, look it up in user_by_sys_id
                    user_by_sys_id = ci_data.get('user_by_sys_id', {})
                    sys_id_record = user_by_sys_id.get(user)
                    if sys_id_record:
                        display_name = sys_id_record.get('name', user)
                        # Also get the actual username for proper tracking
                        actual_username = sys_id_record.get('user_name', user)
                    else:
                        display_name = user
                        actual_username = user
                else:
                    actual_username = user
                
                user_scores.append({
                    'user': actual_username,  # Use the actual username, not sys_id
                    'user_sys_id': user_sys_id or user,  # Include sys_id for tracking
                    'display_name': display_name,
                    'score': score,
                    'activity_count': activity['count'],
                    'last_activity_days_ago': (datetime.now() - activity['last_activity']).days if activity['last_activity'] else 999,
                    'ownership_changes': ownership_changes,
                    'fields_modified': len(activity['fields']),
                    'department': self._clean_department_field(user_details.get('department', 'Unknown'))
                })
                
                # Debug logging for first few recommendations
                if len(user_scores) <= 3:
                    print(f"DEBUG recommendation {len(user_scores)}: user='{user}', user_sys_id='{user_sys_id}', "
                          f"display_name_from_mapping='{username_to_display_name.get(user)}', "
                          f"final_display_name='{username_to_display_name.get(user, user)}', "
                          f"department='{user_details.get('department', 'Unknown')}'")

            # Sort by score and return top recommendations
            user_scores.sort(key=lambda x: x['score'], reverse=True)
            
            print(f"DEBUG _recommend_new_owner_from_data: Generated {len(user_scores)} recommendations")
            if user_scores:
                print(f"DEBUG _recommend_new_owner_from_data: Top recommendation: {user_scores[0]}")
            
            # Return up to 3 recommendations
            result = user_scores[:3] if len(user_scores) >= 3 else user_scores
            print(f"DEBUG _recommend_new_owner_from_data: Returning {len(result)} recommendations: {result}")
            return result

        except Exception as e:
            return None

    def get_stale_ci_list(self, labels_df, audit_df, user_df, ci_df, ci_owner_display_names=None):
        """
        Analyze all CIs and return a list of stale CIs with confidence and risk level.
        Args:
            labels_df: DataFrame with columns ['ci_id', 'assigned_owner']
            audit_df: DataFrame of audit records
            user_df: DataFrame of user records
            ci_df: DataFrame of CI records
            ci_owner_display_names: Dict mapping CI IDs to owner display names
        Returns:
            List of dicts, each representing a stale CI with confidence and risk_level
        """
        stale_cis = []
        if ci_owner_display_names is None:
            ci_owner_display_names = {}
            
        # Convert user and CI data to regular dicts first
        user_by_name = {}
        user_by_sys_id = {}
        username_to_display_name = {}  # Create mapping for display names
        for _, u in user_df.iterrows():
            user_dict = {k: v for k, v in u.to_dict().items()}
            if u.get('user_name'):
                user_name = str(u.get('user_name'))
                user_by_name[user_name] = user_dict
                # Map username to display name
                display_name = str(u.get('name', user_name))  # Use 'name' field as display name, fallback to username
                username_to_display_name[user_name] = display_name
            if u.get('sys_id'):
                sys_id = str(u.get('sys_id'))
                user_by_sys_id[sys_id] = user_dict
        
        print(f"DEBUG: Built username_to_display_name mapping with {len(username_to_display_name)} entries")
        if username_to_display_name:
            sample_entries = list(username_to_display_name.items())[:3]
            print(f"DEBUG: Sample username_to_display_name entries: {sample_entries}")
        
        # Build lookup for audit data
        audit_by_ci = {}
        all_user_audit_records = []  # Collect all user profile audit records
        
        for _, row in audit_df.iterrows():
            doc_key = row.get('documentkey')
            
            # Extract the actual document key value if it's a dict
            if isinstance(doc_key, dict):
                doc_key = doc_key.get('value', doc_key.get('display_value', ''))
            
            if doc_key:
                # Convert pandas Series to dict to avoid JSON serialization issues
                audit_record = {k: v for k, v in row.to_dict().items()}
                
                # Debug: Log raw audit record structure for user profile changes
                if row.get('tablename') == 'sys_user' and row.get('fieldname') in ['title', 'department']:
                    print(f"DEBUG: Raw user profile audit record - tablename: {row.get('tablename')}, "
                          f"fieldname: {row.get('fieldname')}, documentkey type: {type(doc_key)}, "
                          f"documentkey value: {doc_key}")
                
                # Clean up all dict fields to extract their values
                for field_name, field_value in audit_record.items():
                    if isinstance(field_value, dict):
                        # For most fields, prefer display_value, fallback to value
                        if field_name == 'sys_created_on':
                            # For dates, prefer the actual datetime value
                            audit_record[field_name] = field_value.get('value', field_value.get('display_value', ''))
                        else:
                            audit_record[field_name] = field_value.get('display_value', field_value.get('value', ''))
                
                # Make sure documentkey is properly set
                audit_record['documentkey'] = str(doc_key)
                
                # Extract user display name from expanded user fields if available
                user_field = row.get('user')  # Get original user field from row
                user_name_field = row.get('user.user_name')  # Get expanded username field
                user_display_name_field = row.get('user.name')  # Get expanded display name field
                
                if isinstance(user_field, dict):
                    # If user is expanded, extract the display name and username
                    user_display_name = user_field.get('display_value', '')
                    user_sys_id = user_field.get('value', '')  # This is the sys_id
                    
                    # Get username from expanded field
                    if isinstance(user_name_field, dict):
                        user_username = user_name_field.get('display_value', user_name_field.get('value', ''))
                    else:
                        user_username = str(user_name_field) if user_name_field else ''
                    
                    # Get display name from expanded field if available
                    if isinstance(user_display_name_field, dict):
                        user_display_name = user_display_name_field.get('display_value', user_display_name_field.get('value', user_display_name))
                    elif user_display_name_field:
                        user_display_name = str(user_display_name_field)
                    
                    # Update the audit record with clean user information
                    audit_record['user'] = user_username or user_sys_id  # Prefer username, fallback to sys_id
                    audit_record['user_display_name'] = user_display_name or user_username or user_sys_id
                    audit_record['user_sys_id'] = user_sys_id
                    
                    # Update the username_to_display_name mapping if we have both
                    if user_username and user_display_name:
                        username_to_display_name[user_username] = user_display_name
                        
                elif user_field:
                    # If user is just a string, try to get display name from user data
                    user_str = str(user_field)
                    audit_record['user'] = user_str
                    audit_record['user_display_name'] = username_to_display_name.get(user_str, user_str)
                    audit_record['user_sys_id'] = user_str  # Might be sys_id
                
                # If this is a user profile change audit record, add to all_user_audit_records
                if audit_record.get('audit_type') == 'user_profile_change' or (
                    audit_record.get('tablename') == 'sys_user' and 
                    audit_record.get('fieldname') in ['title', 'department', 'manager', 'active']
                ):
                    all_user_audit_records.append(audit_record)
                else:
                    # Otherwise it's a CI audit record
                    audit_by_ci.setdefault(str(doc_key), []).append(audit_record)
        
        ci_by_id = {}
        for _, ci in ci_df.iterrows():
            ci_sys_id = ci.get('sys_id')
            # Handle sys_id that might be a dict with display_value/value
            if isinstance(ci_sys_id, dict):
                ci_sys_id = ci_sys_id.get('value', ci_sys_id.get('display_value', ''))
            
            if ci_sys_id:
                ci_by_id[str(ci_sys_id)] = {k: v for k, v in ci.to_dict().items()}
        
        print(f"DEBUG: Built ci_by_id mapping with {len(ci_by_id)} entries")
        print(f"DEBUG: Found {len(all_user_audit_records)} user profile audit records")
        
        # Debug: Show breakdown of user profile changes
        if all_user_audit_records:
            title_count = sum(1 for r in all_user_audit_records if r.get('fieldname') == 'title')
            dept_count = sum(1 for r in all_user_audit_records if r.get('fieldname') == 'department')
            print(f"DEBUG: User profile changes - {title_count} title changes, {dept_count} department changes")
            # Show sample documentkeys
            sample_keys = list(set(r.get('documentkey', '') for r in all_user_audit_records[:10]))
            print(f"DEBUG: Sample user profile change documentkeys: {sample_keys[:5]}")
            
            # Show all fields being tracked
            field_types = set(r.get('fieldname', '') for r in all_user_audit_records)
            print(f"DEBUG: Fields being tracked in user profile changes: {field_types}")
            
            # Show full details of first few records
            for i, record in enumerate(all_user_audit_records[:3]):
                print(f"DEBUG: User profile audit record {i}: fieldname={record.get('fieldname')}, "
                      f"documentkey={record.get('documentkey')}, tablename={record.get('tablename')}")
        
        if ci_by_id:
            sample_ci_id = list(ci_by_id.keys())[0]
            sample_ci_data = ci_by_id[sample_ci_id]
            print(f"DEBUG: Sample CI {sample_ci_id} has keys: {list(sample_ci_data.keys())}")
            if 'name' in sample_ci_data:
                print(f"DEBUG: Sample CI name: {sample_ci_data['name']} (type: {type(sample_ci_data['name'])})")

        for _, label in labels_df.iterrows():
            # Convert label to dict to avoid pandas Series issues
            label_dict = label.to_dict()
            ci_id = label_dict.get('ci_id')
            assigned_owner = label_dict.get('assigned_owner')
            
            ci_info = ci_by_id.get(str(ci_id), {})
            audit_records = audit_by_ci.get(str(ci_id), [])
            user_info = user_by_name.get(str(assigned_owner), {})
            
            # Debug logging for first few CIs to see CI info lookup
            if len(stale_cis) < 3:
                print(f"DEBUG CI Lookup {ci_id}: ci_info keys={list(ci_info.keys()) if ci_info else 'EMPTY'}")
                if ci_info and 'name' in ci_info:
                    print(f"DEBUG CI name field: {ci_info['name']} (type: {type(ci_info['name'])})")
            
            ci_data = {
                'ci_info': ci_info,
                'audit_records': audit_records,
                'user_info': user_info,
                'assigned_owner': assigned_owner,
                'username_to_display_name': username_to_display_name,  # Pass the mapping
                'user_data_context': user_by_name,  # Pass all user data for department lookup
                'user_by_sys_id': user_by_sys_id,  # Pass sys_id mapping for better lookups
                'all_user_audit_records': all_user_audit_records  # Pass all user audit records
            }
            
            result = self.predict_single(ci_data)
            if result.get('is_stale'):
                # Assign risk level based on confidence
                confidence = result.get('confidence', 0)
                if confidence > 0.9:
                    risk_level = 'Critical'
                elif confidence > 0.8:
                    risk_level = 'High'
                elif confidence > 0.7:
                    risk_level = 'Medium'
                else:
                    risk_level = 'Low'
                
                # Ensure all data is JSON serializable
                # Get the display name for the current owner - try CI mapping first, then username mapping
                ci_mapping_result = ci_owner_display_names.get(str(ci_id))
                username_mapping_result = username_to_display_name.get(str(assigned_owner))
                current_owner_display_name = ci_mapping_result or username_mapping_result or str(assigned_owner)
                
                # Debug logging for first few CIs
                if len(stale_cis) < 3:
                    print(f"DEBUG CI {ci_id}: assigned_owner='{assigned_owner}', ci_mapping='{ci_mapping_result}', username_mapping='{username_mapping_result}', final='{current_owner_display_name}'")
                
                # Extract CI name properly (might be a dict with display_value/value)
                ci_name = ci_info.get('name', 'Unknown')
                if isinstance(ci_name, dict):
                    ci_name = ci_name.get('display_value', ci_name.get('value', 'Unknown'))
                
                # Extract CI class properly
                ci_class = ci_info.get('sys_class_name', 'Unknown')
                if isinstance(ci_class, dict):
                    ci_class = ci_class.get('display_value', ci_class.get('value', 'Unknown'))
                
                # Extract CI description properly
                ci_description = ci_info.get('short_description', '')
                if isinstance(ci_description, dict):
                    ci_description = ci_description.get('display_value', ci_description.get('value', ''))
                
                stale_ci_dict = {
                    'ci_id': str(ci_id),
                    'ci_name': str(ci_name),
                    'ci_class': str(ci_class),
                    'ci_description': str(ci_description),
                    'current_owner': current_owner_display_name,
                    'current_owner_username': str(assigned_owner),  # Keep username for technical reference
                    'confidence': float(confidence),
                    'risk_level': str(risk_level),
                    'staleness_reasons': [
                        {
                            'rule_name': str(rule.get('rule', '')),
                            'description': str(rule.get('description', '')),
                            'confidence': float(rule.get('confidence', 0))
                        } for rule in result.get('triggered_rules', [])
                    ],
                    'recommended_owners': self._format_owner_recommendations(result.get('new_owner_recommendation')),
                    'owner_activity_count': int(result.get('features', {}).get('owner_activity_count', 0)),
                    'days_since_owner_activity': int(result.get('features', {}).get('days_since_owner_activity', 999)),
                    'owner_active': bool(result.get('features', {}).get('owner_active', True)),
                    # Enhanced change tracking information
                    'title_changes': self._format_change_details(result.get('features', {}).get('title_changes_details', [])),
                    'department_changes': self._format_change_details(result.get('features', {}).get('department_changes_details', [])),
                    'owner_profile_changes': self._format_change_details(result.get('features', {}).get('owner_profile_changes_details', [])),
                    'title_changes_count': int(result.get('features', {}).get('title_changes_count', 0)),
                    'department_changes_count': int(result.get('features', {}).get('department_changes_count', 0)),
                    'owner_profile_changes_count': int(result.get('features', {}).get('owner_profile_changes_count', 0))
                }

                stale_cis.append(stale_ci_dict)

        return stale_cis

    def _format_owner_recommendations(self, recommendations):
        """Format owner recommendations to be JSON serializable"""
        if not recommendations:
            return []
        
        print(f"DEBUG _format_owner_recommendations: Input type: {type(recommendations)}")
        print(f"DEBUG _format_owner_recommendations: Input value: {recommendations}")
        
        # Handle both single recommendation (old format) and multiple recommendations (new format)
        if isinstance(recommendations, dict):
            # Old format - single recommendation
            formatted = [{
                'username': str(recommendations.get('user', '')),
                'user_sys_id': str(recommendations.get('user_sys_id', '')),
                'display_name': str(recommendations.get('display_name', recommendations.get('user', ''))),
                'score': int(recommendations.get('score', 0)),
                'activity_count': int(recommendations.get('activity_count', 0)),
                'last_activity_days_ago': int(recommendations.get('last_activity_days_ago', 999)),
                'ownership_changes': int(recommendations.get('ownership_changes', 0)),
                'fields_modified': int(recommendations.get('fields_modified', 0)),
                'department': str(recommendations.get('department', 'Unknown'))
            }]
            print(f"DEBUG _format_owner_recommendations: Formatted single recommendation: {formatted}")
            return formatted
        elif isinstance(recommendations, list):
            # New format - multiple recommendations
            formatted = []
            for i, rec in enumerate(recommendations):
                print(f"DEBUG _format_owner_recommendations: Processing recommendation {i}: {rec}")
                formatted_rec = {
                    'username': str(rec.get('user', '')),
                    'user_sys_id': str(rec.get('user_sys_id', '')),
                    'display_name': str(rec.get('display_name', rec.get('user', ''))),
                    'score': int(rec.get('score', 0)),
                    'activity_count': int(rec.get('activity_count', 0)),
                    'last_activity_days_ago': int(rec.get('last_activity_days_ago', 999)),
                    'ownership_changes': int(rec.get('ownership_changes', 0)),
                    'fields_modified': int(rec.get('fields_modified', 0)),
                    'department': str(rec.get('department', 'Unknown'))
                }
                print(f"DEBUG _format_owner_recommendations: Formatted recommendation {i}: {formatted_rec}")
                formatted.append(formatted_rec)
            print(f"DEBUG _format_owner_recommendations: Final formatted list: {formatted}")
            return formatted
        else:
            print(f"DEBUG _format_owner_recommendations: Unknown type, returning empty list")
            return []

    def _format_change_details(self, changes):
        """Format title/department change details to be JSON serializable"""
        if not changes:
            return []
        
        formatted_changes = []
        for change in changes:
            formatted_change = {
                'user': str(change.get('user', '')),
                'user_sys_id': str(change.get('user_sys_id', '')),
                'field': str(change.get('field', '')),
                'old_value': str(change.get('old_value', '')),
                'new_value': str(change.get('new_value', '')),
                'change_date': str(change.get('change_date', '')),
                'is_owner': bool(change.get('is_owner', False))
            }
            formatted_changes.append(formatted_change)
        
        # Sort by change date (most recent first)
        try:
            formatted_changes.sort(key=lambda x: self._parse_date(x['change_date']), reverse=True)
        except:
            pass  # If date parsing fails, keep original order
        
        return formatted_changes


# Create and save the model
def create_and_save_model():
    """Create the model and save it as pickle file"""
    print("Creating Rule-Based Staleness Detector...")
    
    # Initialize the detector
    detector = RuleBasedStalenessDetector()
    
    # Save as pickle file
    model_filename = 'staleness_detector_model.pkl'
    
    with open(model_filename, 'wb') as f:
        pickle.dump(detector, f)
    
    print(f"Model saved as {model_filename}")
    
    # Test loading the model
    print("Testing model loading...")
    with open(model_filename, 'rb') as f:
        loaded_model = pickle.load(f)
    
    # Test prediction with sample data
    sample_ci_data = {
        'assigned_owner': 'john.doe',
        'audit_records': [
            {
                'user': 'jane.smith',
                'sys_created_on': '2024-06-20 10:30:00',
                'fieldname': 'assigned_to'
            },
            {
                'user': 'jane.smith',
                'sys_created_on': '2024-06-21 14:15:00',
                'fieldname': 'state'
            }
        ],
        'user_info': {
            'active': True
        }
    }
    
    result = loaded_model.predict_single(sample_ci_data)
    print("Test prediction successful!")
    print(f"Sample result: {result}")
    
    return model_filename

if __name__ == "__main__":
    model_file = create_and_save_model()
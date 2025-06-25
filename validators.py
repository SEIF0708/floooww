"""
Input validation utilities for AutoFlow AI Backend
"""
import re
from typing import Dict, List, Tuple, Any
from email_validator import validate_email, EmailNotValidError

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class Validator:
    """
    Comprehensive input validation class
    """
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str, str]:
        """
        Validate email address format and deliverability
        
        Returns:
            Tuple[bool, str, str]: (is_valid, normalized_email, error_message)
        """
        if not email:
            return False, "", "Email is required"
        
        try:
            # Use email-validator library for comprehensive validation
            validated_email = validate_email(email.strip())
            return True, validated_email.email, ""
        except EmailNotValidError as e:
            return False, "", str(e)
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, List[str]]:
        """
        Validate password strength
        
        Returns:
            Tuple[bool, List[str]]: (is_valid, list_of_errors)
        """
        errors = []
        
        if not password:
            errors.append("Password is required")
            return False, errors
        
        # Length requirements
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        if len(password) > 128:
            errors.append("Password must be less than 128 characters long")
        
        # Character requirements
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r"\d", password):
            errors.append("Password must contain at least one number")
        
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password must contain at least one special character")
        
        # Common weak passwords
        weak_patterns = [
            r"^password\d*$",
            r"^123456\d*$",
            r"^qwerty\d*$",
            r"^abc123\d*$",
            r"^welcome\d*$"
        ]
        
        for pattern in weak_patterns:
            if re.match(pattern, password.lower()):
                errors.append("Password is too common. Please choose a stronger password")
                break
        
        # Sequential characters
        if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)", password.lower()):
            errors.append("Password should not contain sequential characters")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_full_name(name: str) -> Tuple[bool, str]:
        """
        Validate full name
        
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not name:
            return False, "Full name is required"
        
        name = name.strip()
        
        if len(name) < 2:
            return False, "Full name must be at least 2 characters long"
        
        if len(name) > 100:
            return False, "Full name must be less than 100 characters long"
        
        # Allow letters, spaces, hyphens, apostrophes, periods, and some international characters
        if not re.match(r"^[a-zA-ZÀ-ÿ\s\-'\.]+$", name):
            return False, "Full name contains invalid characters"
        
        # Must contain at least one letter
        if not re.search(r"[a-zA-ZÀ-ÿ]", name):
            return False, "Full name must contain at least one letter"
        
        # Check for reasonable format (not just spaces or special characters)
        if len(re.sub(r"[^a-zA-ZÀ-ÿ]", "", name)) < 2:
            return False, "Full name must contain at least 2 letters"
        
        return True, ""
    
    @staticmethod
    def validate_phone(phone: str) -> Tuple[bool, str, str]:
        """
        Validate phone number (optional field)
        
        Returns:
            Tuple[bool, str, str]: (is_valid, normalized_phone, error_message)
        """
        if not phone:
            return True, "", ""  # Phone is optional
        
        # Remove all non-digit characters
        digits_only = re.sub(r"\D", "", phone)
        
        # Check length (10-15 digits is reasonable for international numbers)
        if len(digits_only) < 10:
            return False, "", "Phone number must be at least 10 digits"
        
        if len(digits_only) > 15:
            return False, "", "Phone number must be less than 15 digits"
        
        # Format as international number
        if len(digits_only) == 10:
            # Assume US number, add country code
            normalized = f"+1{digits_only}"
        elif len(digits_only) == 11 and digits_only.startswith("1"):
            # US number with country code
            normalized = f"+{digits_only}"
        else:
            # International number
            normalized = f"+{digits_only}"
        
        return True, normalized, ""
    
    @staticmethod
    def validate_json_data(data: Dict[str, Any], required_fields: List[str]) -> Tuple[bool, List[str]]:
        """
        Validate JSON request data
        
        Args:
            data: The JSON data to validate
            required_fields: List of required field names
        
        Returns:
            Tuple[bool, List[str]]: (is_valid, list_of_errors)
        """
        errors = []
        
        if not data:
            errors.append("Request data is required")
            return False, errors
        
        if not isinstance(data, dict):
            errors.append("Request data must be a JSON object")
            return False, errors
        
        # Check required fields
        for field in required_fields:
            if field not in data:
                errors.append(f"Field '{field}' is required")
            elif data[field] is None:
                errors.append(f"Field '{field}' cannot be null")
            elif isinstance(data[field], str) and not data[field].strip():
                errors.append(f"Field '{field}' cannot be empty")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def sanitize_string(text: str, max_length: int = None, allow_html: bool = False) -> str:
        """
        Sanitize string input
        
        Args:
            text: The text to sanitize
            max_length: Maximum allowed length
            allow_html: Whether to allow HTML tags
        
        Returns:
            str: Sanitized text
        """
        if not text:
            return ""
        
        # Strip whitespace
        sanitized = text.strip()
        
        # Remove HTML tags if not allowed
        if not allow_html:
            sanitized = re.sub(r"<[^>]*>", "", sanitized)
        
        # Limit length
        if max_length and len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized
    
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, str]:
        """
        Validate URL format
        
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not url:
            return False, "URL is required"
        
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(url):
            return False, "Invalid URL format"
        
        return True, ""

class RequestValidator:
    """
    Request-specific validation helpers
    """
    
    @staticmethod
    def validate_registration_data(data: Dict[str, Any]) -> Tuple[bool, Dict[str, str]]:
        """
        Validate user registration data
        
        Returns:
            Tuple[bool, Dict[str, str]]: (is_valid, field_errors)
        """
        errors = {}
        
        # Validate required fields
        is_valid, field_errors = Validator.validate_json_data(
            data, ['fullName', 'email', 'password']
        )
        
        if not is_valid:
            return False, {'general': field_errors}
        
        # Validate full name
        name_valid, name_error = Validator.validate_full_name(data.get('fullName', ''))
        if not name_valid:
            errors['fullName'] = name_error
        
        # Validate email
        email_valid, normalized_email, email_error = Validator.validate_email(data.get('email', ''))
        if not email_valid:
            errors['email'] = email_error
        
        # Validate password
        password_valid, password_errors = Validator.validate_password(data.get('password', ''))
        if not password_valid:
            errors['password'] = password_errors[0] if password_errors else "Invalid password"
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_login_data(data: Dict[str, Any]) -> Tuple[bool, Dict[str, str]]:
        """
        Validate user login data
        
        Returns:
            Tuple[bool, Dict[str, str]]: (is_valid, field_errors)
        """
        errors = {}
        
        # Validate required fields
        is_valid, field_errors = Validator.validate_json_data(
            data, ['email', 'password']
        )
        
        if not is_valid:
            return False, {'general': field_errors}
        
        # Basic email format check (don't need full validation for login)
        email = data.get('email', '').strip()
        if not email or '@' not in email:
            errors['email'] = "Valid email address is required"
        
        # Password presence check
        password = data.get('password', '')
        if not password:
            errors['password'] = "Password is required"
        
        return len(errors) == 0, errors


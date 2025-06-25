from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import check_password_hash, generate_password_hash
from email_validator import validate_email, EmailNotValidError
from src.models.user import db, User
from datetime import datetime
import re

auth_bp = Blueprint('auth', __name__)

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def validate_full_name(name):
    """Validate full name"""
    if not name or len(name.strip()) < 2:
        return False, "Full name must be at least 2 characters long"
    if len(name.strip()) > 100:
        return False, "Full name must be less than 100 characters"
    if not re.match(r"^[a-zA-Z\s\-'\.]+$", name.strip()):
        return False, "Full name can only contain letters, spaces, hyphens, apostrophes, and periods"
    return True, "Full name is valid"

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract and validate required fields
        full_name = data.get('fullName', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validate full name
        name_valid, name_message = validate_full_name(full_name)
        if not name_valid:
            return jsonify({'error': name_message}), 400
        
        # Validate email
        try:
            validated_email = validate_email(email)
            email = validated_email.email
        except EmailNotValidError:
            return jsonify({'error': 'Invalid email address'}), 400
        
        # Validate password
        password_valid, password_message = validate_password(password)
        if not password_valid:
            return jsonify({'error': password_message}), 400
        
        # Check if user already exists
        existing_user = User.find_by_email(email)
        if existing_user:
            return jsonify({'error': 'Email address is already registered'}), 409
        
        # Create new user
        password_hash = generate_password_hash(password).decode('utf-8')
        
        new_user = User(
            full_name=full_name,
            email=email,
            password_hash=password_hash
        )
        
        # Generate verification token
        new_user.generate_verification_token()
        
        # Save to database
        db.session.add(new_user)
        db.session.commit()
        
        # Create JWT tokens
        access_token = create_access_token(identity=new_user.id)
        refresh_token = create_refresh_token(identity=new_user.id)
        
        return jsonify({
            'message': 'User registered successfully',
            'user': new_user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed. Please try again.'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and return JWT tokens"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Find user by email
        user = User.find_by_email(email)
        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Check if user is active
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated. Please contact support.'}), 401
        
        # Verify password
        if not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Update last login
        user.update_last_login()
        
        # Create JWT tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed. Please try again.'}), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token"""
    try:
        current_user_id = get_jwt_identity()
        user = User.find_by_id(current_user_id)
        
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 404
        
        # Create new access token
        access_token = create_access_token(identity=current_user_id)
        
        return jsonify({
            'access_token': access_token
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user (client-side token removal)"""
    try:
        # In a more sophisticated setup, you might want to blacklist the token
        # For now, we'll just return a success message
        # The client should remove the token from storage
        
        return jsonify({
            'message': 'Logout successful'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Validate email format
        try:
            validated_email = validate_email(email)
            email = validated_email.email
        except EmailNotValidError:
            return jsonify({'error': 'Invalid email address'}), 400
        
        # Find user by email
        user = User.find_by_email(email)
        
        # Always return success to prevent email enumeration
        # In production, you would send an email with reset instructions
        if user and user.is_active:
            # Generate reset token
            reset_token = user.generate_reset_token()
            db.session.commit()
            
            # In production, send email with reset link
            # For demo purposes, we'll just log the token
            current_app.logger.info(f"Password reset token for {email}: {reset_token}")
        
        return jsonify({
            'message': 'If an account with that email exists, a password reset link has been sent.'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Forgot password error: {str(e)}")
        return jsonify({'error': 'Password reset request failed'}), 500

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset password using reset token"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip().lower()
        token = data.get('token', '').strip()
        new_password = data.get('password', '')
        
        if not all([email, token, new_password]):
            return jsonify({'error': 'Email, token, and new password are required'}), 400
        
        # Validate new password
        password_valid, password_message = validate_password(new_password)
        if not password_valid:
            return jsonify({'error': password_message}), 400
        
        # Find user by email
        user = User.find_by_email(email)
        if not user:
            return jsonify({'error': 'Invalid reset token'}), 400
        
        # Verify reset token
        if not user.verify_reset_token(token):
            return jsonify({'error': 'Invalid or expired reset token'}), 400
        
        # Update password
        user.password_hash = generate_password_hash(new_password).decode('utf-8')
        user.clear_reset_token()
        db.session.commit()
        
        return jsonify({
            'message': 'Password reset successful'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Password reset error: {str(e)}")
        return jsonify({'error': 'Password reset failed'}), 500

@auth_bp.route('/verify-email', methods=['POST'])
def verify_email():
    """Verify email address using verification token"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip().lower()
        token = data.get('token', '').strip()
        
        if not email or not token:
            return jsonify({'error': 'Email and token are required'}), 400
        
        # Find user by email
        user = User.find_by_email(email)
        if not user:
            return jsonify({'error': 'Invalid verification token'}), 400
        
        # Check if already verified
        if user.email_verified:
            return jsonify({'message': 'Email is already verified'}), 200
        
        # Verify token
        if user.verification_token != token:
            return jsonify({'error': 'Invalid verification token'}), 400
        
        # Mark email as verified
        user.email_verified = True
        user.verification_token = None
        db.session.commit()
        
        return jsonify({
            'message': 'Email verified successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Email verification error: {str(e)}")
        return jsonify({'error': 'Email verification failed'}), 500


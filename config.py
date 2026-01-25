"""
Demo config with hardcoded secrets.
Fixpoint will automatically detect and fix these!
"""
import os


# =============================================================================
# VULNERABLE: Hardcoded secrets that Fixpoint will fix
# =============================================================================

# API Keys (demo values - obviously fake)
API_KEY = "my_hardcoded_api_key_12345_CHANGEME"
SECRET_KEY = "super_secret_key_12345_do_not_share"

# Database credentials
DATABASE_PASSWORD = "MySecretDbP@ssw0rd123!"
DB_CONNECTION_STRING = "postgresql://admin:secretpass123@localhost:5432/mydb"

# AWS credentials (using AWS documented example keys)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Third-party service tokens (demo values)
PAYMENT_API_KEY = "payment_key_demo_abc123_FIXME"
AUTH_TOKEN = "auth_token_hardcoded_xyz789_CHANGEME"
WEBHOOK_SECRET = "webhook_secret_demo_value_123"

# Generic secrets
ENCRYPTION_KEY = "aes256_encryption_key_very_secret"
JWT_SECRET = "jwt_signing_secret_never_expose_this"


# =============================================================================
# Configuration using secrets (these will be populated by Fixpoint fixes)
# =============================================================================

class AppConfig:
    """Application configuration."""
    
    # These use the hardcoded values above - Fixpoint will fix them
    def __init__(self):
        self.api_key = API_KEY
        self.secret_key = SECRET_KEY
        self.db_password = DATABASE_PASSWORD
    
    def get_payment_key(self):
        return PAYMENT_API_KEY
    
    def get_aws_credentials(self):
        return {
            "access_key": AWS_ACCESS_KEY_ID,
            "secret_key": AWS_SECRET_ACCESS_KEY,
        }


# =============================================================================
# SAFE: Already using environment variables (Fixpoint will skip these)
# =============================================================================

SAFE_API_KEY = os.environ.get("API_KEY")
SAFE_DB_PASSWORD = os.environ.get("DATABASE_PASSWORD", "default_for_dev")
SAFE_JWT_SECRET = os.getenv("JWT_SECRET")


if __name__ == "__main__":
    config = AppConfig()
    print(f"Config loaded with API key: {config.api_key[:10]}...")

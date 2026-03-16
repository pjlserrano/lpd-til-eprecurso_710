"""Simple password manager CLI module.

This module provides a minimal password manager that stores entries (URL, user, password)
with all fields encrypted using an asymmetric RSA key pair.

Access to the stored passwords requires a TOTP 2FA code (pyotp).
"""

from .manager import run_password_manager

__all__ = ["run_password_manager"]

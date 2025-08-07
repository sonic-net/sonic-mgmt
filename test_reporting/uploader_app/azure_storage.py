#!/usr/bin/env python3

import os
import logging
import secrets
import re
from typing import Dict, Any, Optional
from azure.data.tables import TableServiceClient, TableEntity
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ResourceNotFoundError, ResourceExistsError

logger = logging.getLogger(__name__)

class AzureUserStorage:
    """Azure-based user storage using Table Storage for basic info and Key Vault for secrets."""

    def __init__(self):
        """Initialize Azure clients."""
        # Get configuration from environment variables
        self.storage_account_url = os.environ.get('AZURE_STORAGE_ACCOUNT_URL')
        self.key_vault_url = os.environ.get('AZURE_KEY_VAULT_URL')
        self.table_name = os.environ.get('AZURE_TABLE_NAME', 'users')

        if not self.storage_account_url:
            raise ValueError("AZURE_STORAGE_ACCOUNT_URL environment variable is required")
        if not self.key_vault_url:
            raise ValueError("AZURE_KEY_VAULT_URL environment variable is required")

        # Initialize Azure credential
        self.credential = DefaultAzureCredential()

        # Initialize Table Storage client
        self.table_service = TableServiceClient(
            endpoint=self.storage_account_url,
            credential=self.credential
        )
        self.table_client = self.table_service.get_table_client(self.table_name)

        # Initialize Key Vault client
        self.keyvault_client = SecretClient(
            vault_url=self.key_vault_url,
            credential=self.credential
        )

        # Ensure table exists
        self._ensure_table_exists()

    def _ensure_table_exists(self):
        """Ensure the users table exists."""
        try:
            self.table_service.create_table(self.table_name)
            logger.info(f"Created table: {self.table_name}")
        except ResourceExistsError:
            logger.debug(f"Table {self.table_name} already exists")
        except Exception as e:
            logger.error(f"Failed to create/access table {self.table_name}: {e}")
            raise

    def _sanitize_keyvault_name(self, name: str) -> str:
        """Sanitize a string to be valid for Azure Key Vault naming.

        Azure Key Vault secret names only allow alphanumeric characters (a–z, A–Z, 0–9)
        and hyphens (-). This method sanitizes any string by converting all special
        characters to hyphens.

        Args:
            name: The string to sanitize

        Returns:
            str: Sanitized string suitable for Key Vault naming
        """
        # Replace any non-alphanumeric character (except hyphens) with hyphens
        sanitized_name = re.sub(r'[^a-zA-Z0-9-]', '-', name)
        # Replace multiple consecutive hyphens with a single hyphen
        sanitized_name = re.sub(r'-+', '-', sanitized_name)
        # Remove leading/trailing hyphens
        sanitized_name = sanitized_name.strip('-')

        return sanitized_name.lower()

    def _get_keyvault_secret_name(self, username: str, secret_type: str) -> str:
        """Generate Key Vault secret name for user secrets.

        Args:
            username: The username
            secret_type: The type of secret (e.g., 'initial-password', 'totp-secret')

        Returns:
            str: Sanitized secret name for Key Vault
        """
        sanitized_username = self._sanitize_keyvault_name(username)
        sanitized_secret_type = self._sanitize_keyvault_name(secret_type)

        return f"user-{sanitized_username}-{sanitized_secret_type}".lower()

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user basic information from Table Storage."""
        try:
            entity = self.table_client.get_entity(
                partition_key="users",
                row_key=username
            )

            # Convert TableEntity to dict and add secrets
            user_data = {
                "username": entity["RowKey"],
                "totp_enabled": entity.get("totp_enabled", False),
                "created_at": entity.get("created_at"),
                "last_login": entity.get("last_login"),
                "initial_password": self._get_secret(username, "initial-password"),
                "totp_secret": self._get_secret(username, "totp-secret")
            }

            return user_data

        except ResourceNotFoundError:
            return None
        except Exception as e:
            logger.error(f"Failed to get user {username}: {e}")
            return None

    def create_user(self, username: str, initial_password: str, totp_enabled: bool = False) -> bool:
        """Create a new user with basic info in Table Storage and secrets in Key Vault."""
        try:
            # Store basic information in Table Storage
            entity = TableEntity()
            entity["PartitionKey"] = "users"
            entity["RowKey"] = username
            entity["totp_enabled"] = totp_enabled
            entity["created_at"] = self._get_current_timestamp()
            entity["last_login"] = None

            self.table_client.create_entity(entity)

            # Store secrets in Key Vault
            self._set_secret(username, "initial-password", initial_password)

            logger.info(f"Created user: {username}")
            return True

        except ResourceExistsError:
            logger.warning(f"User {username} already exists")
            return False
        except Exception as e:
            logger.error(f"Failed to create user {username}: {e}")
            return False

    def update_user(self, username: str, **kwargs) -> bool:
        """Update user information."""
        try:
            # Get existing entity
            entity = self.table_client.get_entity(
                partition_key="users",
                row_key=username
            )

            # Update basic fields in Table Storage
            table_fields = ["totp_enabled", "last_login"]
            secret_fields = ["initial_password", "totp_secret"]

            updated = False

            for key, value in kwargs.items():
                if key in table_fields:
                    entity[key] = value
                    updated = True
                elif key in secret_fields:
                    secret_type = key.replace("_", "-")
                    self._set_secret(username, secret_type, value)
                    updated = True

            if updated:
                # Update timestamp
                entity["updated_at"] = self._get_current_timestamp()
                self.table_client.update_entity(entity, mode="replace")
                logger.info(f"Updated user: {username}")

            return updated

        except ResourceNotFoundError:
            logger.error(f"User {username} not found for update")
            return False
        except Exception as e:
            logger.error(f"Failed to update user {username}: {e}")
            return False

    def _get_secret(self, username: str, secret_type: str) -> Optional[str]:
        """Get secret from Key Vault."""
        try:
            secret_name = self._get_keyvault_secret_name(username, secret_type)
            secret = self.keyvault_client.get_secret(secret_name)
            return secret.value
        except ResourceNotFoundError:
            return None
        except Exception as e:
            logger.error(f"Failed to get secret {secret_type} for user {username}: {e}")
            return None

    def _set_secret(self, username: str, secret_type: str, value: Optional[str]) -> bool:
        """Set secret in Key Vault. If value is None, delete the secret."""
        try:
            secret_name = self._get_keyvault_secret_name(username, secret_type)

            if value is None:
                # Delete the secret if value is None
                try:
                    # First soft delete the secret
                    delete_operation = self.keyvault_client.begin_delete_secret(secret_name)
                    # Wait for the delete operation to complete
                    delete_operation.wait()
                    # Then permanently purge it to avoid conflicts
                    self.keyvault_client.purge_deleted_secret(secret_name)
                    logger.debug(f"Permanently deleted secret {secret_type} for user {username}")
                except ResourceNotFoundError:
                    # Secret doesn't exist, that's fine
                    logger.debug(f"Secret {secret_type} for user {username} doesn't exist, no need to delete")
                except Exception as e:
                    logger.warning(f"Failed to delete secret {secret_type} for user {username}: {e}")
                    return False
            else:
                # Set the secret with the provided value
                self.keyvault_client.set_secret(secret_name, value)
                logger.debug(f"Set secret {secret_type} for user {username}")

            return True
        except Exception as e:
            logger.error(f"Failed to set secret {secret_type} for user {username}: {e}")
            return False

    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    def get_all_users(self) -> list:
        """Get all users from Table Storage."""
        try:
            entities = self.table_client.list_entities()
            users = []
            for entity in entities:
                user_data = {
                    "username": entity["RowKey"],
                    "totp_enabled": entity.get("totp_enabled", False),
                    "created_at": entity.get("created_at"),
                    "last_login": entity.get("last_login"),
                    "updated_at": entity.get("updated_at")
                }
                users.append(user_data)
            return users
        except Exception as e:
            logger.error(f"Failed to get all users: {e}")
            return []

    def delete_user(self, username: str) -> bool:
        """Delete a user and their secrets."""
        try:
            # Delete from Table Storage
            self.table_client.delete_entity(
                partition_key="users",
                row_key=username
            )

            # Delete secrets from Key Vault
            secret_types = ["initial-password", "totp-secret"]
            for secret_type in secret_types:
                try:
                    secret_name = self._get_keyvault_secret_name(username, secret_type)
                    # First soft delete the secret
                    delete_operation = self.keyvault_client.begin_delete_secret(secret_name)
                    # Wait for the delete operation to complete
                    delete_operation.wait()
                    # Then permanently purge it
                    self.keyvault_client.purge_deleted_secret(secret_name)
                except ResourceNotFoundError:
                    # Secret doesn't exist, that's fine
                    pass
                except Exception as e:
                    logger.warning(f"Failed to delete secret {secret_type} for user {username}: {e}")

            logger.info(f"Deleted user: {username}")
            return True

        except ResourceNotFoundError:
            logger.warning(f"User {username} not found for deletion")
            return False
        except Exception as e:
            logger.error(f"Failed to delete user {username}: {e}")
            return False

    def get_flask_secret_key(self) -> str:
        """Get Flask secret key from Key Vault."""
        try:
            secret = self.keyvault_client.get_secret("flask-secret-key")
            return secret.value
        except ResourceNotFoundError:
            logger.warning("Flask secret key not found in Key Vault, generating new one")
            # Generate a new secret key and store it
            new_secret = secrets.token_urlsafe(32)
            try:
                self.keyvault_client.set_secret("flask-secret-key", new_secret)
                logger.info("Generated and stored new Flask secret key in Key Vault")
                return new_secret
            except Exception as e:
                logger.error(f"Failed to store new Flask secret key: {e}")
                raise
        except Exception as e:
            logger.error(f"Failed to get Flask secret key from Key Vault: {e}")
            raise

    def set_secret(self, secret_name: str, secret_value: str) -> bool:
        """Set a generic secret in Key Vault. Will overwrite if exists.

        Args:
            secret_name: Name of the secret (will be sanitized for Key Vault)
            secret_value: Value of the secret

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            sanitized_name = self._sanitize_keyvault_name(secret_name)

            self.keyvault_client.set_secret(sanitized_name, secret_value)
            logger.info(f"Successfully set secret: {sanitized_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to set secret {secret_name}: {e}")
            return False

    def get_secret(self, secret_name: str) -> Optional[str]:
        """Get a generic secret from Key Vault.

        Args:
            secret_name: Name of the secret (will be sanitized for Key Vault)

        Returns:
            str: Secret value if found, None otherwise
        """
        try:
            sanitized_name = self._sanitize_keyvault_name(secret_name)

            secret = self.keyvault_client.get_secret(sanitized_name)
            return secret.value
        except ResourceNotFoundError:
            logger.debug(f"Secret {sanitized_name} not found in Key Vault")
            return None
        except Exception as e:
            logger.error(f"Failed to get secret {secret_name}: {e}")
            return None

    def reset_all_data(self) -> bool:
        """Reset all data - delete all users and ALL secrets. FOR TESTING/DEBUGGING ONLY."""
        if os.environ.get('FLASK_ENV', None) != 'development':
            logger.error("reset_all_data can only be run in a development environment")
            return False

        try:
            deleted_users_count = 0
            deleted_secrets_count = 0

            # Delete all users from Table Storage
            try:
                logger.info("Deleting all users from Table Storage...")
                entities = self.table_client.list_entities()
                for entity in entities:
                    try:
                        self.table_client.delete_entity(
                            partition_key=entity["PartitionKey"],
                            row_key=entity["RowKey"]
                        )
                        deleted_users_count += 1
                        logger.info(f"Deleted user from table: {entity['RowKey']}")
                    except Exception as e:
                        logger.warning(f"Failed to delete user {entity['RowKey']} from table: {e}")
            except Exception as e:
                logger.warning(f"Failed to list users from table: {e}")

            # Delete ALL secrets from Key Vault (except flask-secret-key)
            try:
                # First, handle active secrets
                logger.info("Deleting all secrets from Key Vault...")
                secret_properties = self.keyvault_client.list_properties_of_secrets()

                for secret_property in secret_properties:
                    secret_name = secret_property.name

                    # Skip flask-secret-key - keep it for the application to function
                    if secret_name == "flask-secret-key":
                        continue

                    if secret_name == "RESET-KEY":
                        continue

                    try:
                        logger.info(f"Deleting secret: {secret_name}")
                        # First soft delete the secret
                        delete_operation = self.keyvault_client.begin_delete_secret(secret_name)
                        # Wait for the delete operation to complete
                        delete_operation.wait()
                        # Then permanently purge it
                        self.keyvault_client.purge_deleted_secret(secret_name)
                        deleted_secrets_count += 1
                        logger.info(f"Permanently deleted secret: {secret_name}")
                    except ResourceNotFoundError:
                        # Secret doesn't exist, that's fine
                        pass
                    except Exception as e:
                        logger.warning(f"Failed to delete secret {secret_name}: {e}")

                # Now handle secrets in recoverable (soft-deleted) state
                logger.info("Purging recoverable secrets from Key Vault...")
                deleted_secrets = self.keyvault_client.list_deleted_secrets()

                for deleted_secret in deleted_secrets:
                    secret_name = deleted_secret.name

                    # Skip flask-secret-key - keep it for the application to function
                    if secret_name == "flask-secret-key":
                        continue

                    try:
                        logger.info(f"Purging recoverable secret: {secret_name}")
                        self.keyvault_client.purge_deleted_secret(secret_name)
                        deleted_secrets_count += 1
                        logger.info(f"Permanently purged recoverable secret: {secret_name}")
                    except ResourceNotFoundError:
                        # Secret doesn't exist in deleted state, that's fine
                        pass
                    except Exception as e:
                        logger.warning(f"Failed to purge recoverable secret {secret_name}: {e}")

            except Exception as e:
                logger.warning(f"Failed to list secrets from Key Vault: {e}")

            logger.warning(f"RESET COMPLETE: Deleted {deleted_users_count} users and {deleted_secrets_count} secrets")
            return True

        except Exception as e:
            logger.error(f"Failed to reset all data: {e}")
            return False

# Global instance
user_storage_instance = None

def get_user_storage():
    """Get or create the global user storage instance."""
    global user_storage_instance
    if user_storage_instance is None:
        user_storage_instance = AzureUserStorage()
        logger.info("Initialized Azure user storage")
    return user_storage_instance

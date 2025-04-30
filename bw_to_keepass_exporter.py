"""
Enhanced Bitwarden to KeePass exporter with improved error handling,
performance, and additional features.
"""

import argparse
import subprocess
import json
import os
import sys
import io
import getpass
import logging
import base64
import binascii
import textwrap
import re
from datetime import datetime, timezone
# noinspection PyUnresolvedReferences
from typing import Dict, List, Any, Optional
# Just with a possible purpose of merging into one script
# weird otherwise

# from bw_session import BwSession
try:
    # noinspection PyUnresolvedReferences,PyUnboundLocalVariable
    BwSession  # Just testing name existence
except NameError:
    from bw_session import BwSession

# Add pykeepass import with error handling
try:
    import pykeepass
except ImportError:
    print("Required package 'pykeepass' is not installed.")
    install_prompt = input("Would you like to install it now? (y/n): ").strip().lower()
    if install_prompt in ['y', 'yes']:
        try:
            print("Attempting to install pykeepass...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pykeepass"])
            print("Installation successful. Importing pykeepass...")
            import pykeepass
        except Exception as e:
            print(f"Failed to install pykeepass: {str(e)}")
            print("Please install it manually with: pip install pykeepass")
            sys.exit(1)
    else:
        print("Please install pykeepass manually with: pip install pykeepass")
        sys.exit(1)

# Global constant for sensitive field patterns
SENSITIVE_PATTERNS = [
    # Password and key related
    r'(?i)cred',
    r'(?i)pass',  # Covers password, passphrase, passcode
    r'(?i)secret',
    r'(?i)key',  # Covers api.key, access.token, etc.
    r'(?i)token',
    r'(?i)pin',
    r'(?i)seed',
    r'(?i)private',
    r'(?i)crypt',
    r'(?i)hash',
    r'(?i)salt',
    r'(?i)api',

    # Authentication related
    r'(?i)auth',
    r'(?i)factor',
    r'(?i)2fa',
    r'(?i)mfa',
    r'(?i)otp',

    # Financial/card related
    r'(?i)cvv',
    r'(?i)cvc',
    r'(?i)csc',
    r'(?i)cid',
    r'(?i)security',
    r'(?i)code',
    r'(?i)verification',

    # Crypto related
    r'(?i)wallet',
    r'(?i)mnemonic',
    r'(?i)phrase',
    r'(?i)word',

    # Personal identifiers
    r'(?i)ssn',
    r'(?i)social',
    r'(?i)tax.?id',
    r'(?i)license',

    # Recovery
    r'(?i)recovery',
    r'(?i)backup',
    # Certificate data
    r'(?i)cert'

]

# Set up logging
# Set up logging with proper encoding handling
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"bw_export_{datetime.now().strftime('%Y%m%d')}.log", encoding='utf-8'),
        # Use StreamHandler with proper encoding for console output
        logging.StreamHandler(stream=io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8'))
    ]
)


logger = logging.getLogger(__name__)


# noinspection PyShadowingNames
class Bitwarden2KeePassExporter:
    """Export Bitwarden vault to KeePass database."""

    def __init__(self, output_path: str = None, keyfile_path: str = None,
                 debug: bool = False, batch_size: int = 100, bw_path: str = None,
                 date_since: str = None):
        """
        Initialize the exporter.

        Args:
            output_path: Path for the output KeePass file
            keyfile_path: Optional path for a KeePass keyfile
            debug: Enable debug logging
            batch_size: Number of items to process in one batch
            bw_path: Custom path to Bitwarden CLI executable
            date_since: Process only items modified on or after this date (YYYY-MM-DD)
        """
        if output_path is None:
            current_date = datetime.now().strftime('%Y%m%d')
            if date_since:
                # Convert date_since from YYYY-MM-DD to YYYYMMDD format
                formatted_date_since = date_since.replace('-', '')
                # Add suffix for partial exports
                self.output_path = f"bw_export_{current_date}-partial_from_{formatted_date_since}.kdbx"
            else:
                # Standard name for full exports
                self.output_path = f"bw_export_{current_date}.kdbx"
        else:
            # If output path is explicitly provided, respect it but still add suffix if needed
            if date_since:
                # Convert date_since from YYYY-MM-DD to YYYYMMDD format
                formatted_date_since = date_since.replace('-', '')
                # Split the path to insert the suffix before the extension
                base, ext = os.path.splitext(output_path)
                self.output_path = f"{base}-partial_from_{formatted_date_since}{ext}"
            else:
                self.output_path = output_path

        self.keyfile_path = keyfile_path
        self.batch_size = batch_size
        self.bw_path = bw_path
        self.date_since = date_since
        self.bw = None
        self.kp = None
        self.folders_dict = {}

        self.stats = {
            "bw_folders": 0,
            "bw_items": 0,
            "bw_attachments": 0,
            "bw_passkeys": 0,
            "bw_ssh_keys": 0,
            "bw_totp": 0,
            "kp_groups": 0,
            "kp_entries": 0,
            "kp_attachments": 0,
            "kp_passkeys": 0,
            "kp_ssh_keys": 0,
            "kp_totp": 0,
            "errors": 0,
            "skipped_items": 0  # Add counter for skipped items
        }

        if debug:
            logger.setLevel(logging.DEBUG)

    def connect_bitwarden(self) -> None:
        """Initialize and log in to Bitwarden."""
        try:
            self.bw = BwSession(cli_path=self.bw_path)
            logger.info(f"Using Bitwarden CLI from: {self.bw.cli_path}")

            # Check status first to avoid unnecessary login prompts
            status = self.bw.check_status()
            if status.get("status") == "unauthenticated" or not self.bw.session:
                logger.info("Authentication required, logging in...")
                self.bw.login()
            else:
                logger.info(f"Already authenticated with status: {status.get('status')}")

            self.bw.sync()
            logger.info("Connected to Bitwarden and synced vault")
        except Exception as e:
            logger.error(f"Failed to connect to Bitwarden: {str(e)}")
            sys.exit(1)

    def setup_keepass(self) -> None:
        """Set up the KeePass database."""
        try:
            password = getpass.getpass("Enter a new KeePass database password: ")
            
            # Add option for keyfile
            if self.keyfile_path:
                from secrets import token_bytes
                with open(self.keyfile_path, 'wb') as f:
                    f.write(token_bytes(32))
                logger.info(f"Created KeePass keyfile at {self.keyfile_path}")
                self.kp = pykeepass.create_database(self.output_path, password=password, keyfile=self.keyfile_path)
            else:
                self.kp = pykeepass.create_database(self.output_path, password=password)
                
            logger.info(f"Created new KeePass database at {self.output_path}")
        except Exception as e:
            logger.error(f"Failed to set up KeePass database: {str(e)}")
            sys.exit(1)

    def process_folders(self) -> None:
        """Process all folders from Bitwarden."""
        try:
            folder_list_raw = self.bw.list_folders()
            folders = json.loads(folder_list_raw)
            
            self.folders_dict = {}
            for f in folders:
                folder_id = f.get('id')
                folder_name = f.get('name', '')
                folder_split = folder_name.split('/') if folder_name else []
                self.folders_dict[folder_id] = {
                    'id': folder_id,
                    'name': folder_name,
                    'split': folder_split
                }
            
            self.stats["bw_folders"] = len(folders) - 2  # without root folder and "No folder"
            logger.info(f"Processed {self.stats['bw_folders']} Bitwarden folders")
        except Exception as e:
            logger.error(f"Failed to process folders: {str(e)}")
            sys.exit(1)

    def get_or_create_group(self, folder_path: List[str]) -> pykeepass.Group:
        """
        Get or create a group path in KeePass.
        
        Args:
            folder_path: List of folder names forming a path
            
        Returns:
            The KeePass group object
        """
        group = self.kp.root_group
        for part in folder_path:
            found = self.kp.find_groups(name=part, group=group, first=True)
            group = found if found else self.kp.add_group(group, part)
        return group

    @staticmethod
    def make_unique_title(group: pykeepass.Group, title: str) -> str:
        """
        Ensure a unique title within a group.
        
        Args:
            group: The KeePass group
            title: The proposed title
            
        Returns:
            A unique title string
        """
        existing_titles = {e.title for e in group.entries}
        if title not in existing_titles:
            return title
        suffix = 1
        while f"{title} ({suffix})" in existing_titles:
            suffix += 1
        return f"{title} ({suffix})"
        
    @staticmethod
    def _is_sensitive_field(field_name: str) -> bool:
        if not field_name:
            return False
        return any(re.search(pattern, field_name) for pattern in SENSITIVE_PATTERNS)

    def _add_custom_fields(self, entry: pykeepass.Entry, fields: list) -> int:
        """
        Add custom fields to a KeePass entry, handling duplicates properly.
        
        Args:
            entry: The KeePass entry
            fields: List of field dictionaries from Bitwarden
            
        Returns:
            int: Number of fields added
        """
        added_count = 0
        
        for field in fields or []:
            name = field.get("name", "")
            value = field.get("value", "")
            field_type = field.get("type", 0)  # 0=text, 1=hidden, 2=boolean
            
            # Skip empty fields
            if not name or value is None:
                continue
                
            # Check for duplicate field name using entry's existing properties
            original_name = name
            suffix = 1
            
            # Get the current custom properties directly from the entry
            existing_properties = entry.custom_properties or {}
            
            while name in existing_properties:
                name = f"{original_name} ({suffix})"
                suffix += 1
            
            # Determine if the field should be protected
            is_protected = (field_type == 1) or self._is_sensitive_field(name)
            
            # Add the field to the entry
            entry.set_custom_property(name, value, protect=is_protected)
            
            if name != original_name:
                logger.debug(f"Renamed duplicate field '{original_name}' to '{name}'")
                
            added_count += 1
            
        return added_count

    def extract_and_add_passkey_data(self, item: Dict[str, Any], entry: pykeepass.Entry) -> None:
        """
        Extract passkey data from Bitwarden item and add it to KeePass entry using
        the standard KeePassXC/Strongbox KPEX_PASSKEY_* fields.
        
        Args:
            item: The Bitwarden item data dictionary
            entry: The KeePass entry to add passkey data to
        """
        # Check if this item has passkey data
        login = item.get("login", {})
        
        # Passkeys are stored in the "fido2Credentials" field of login items
        fido2_credentials = login.get("fido2Credentials", [])
        
        if not fido2_credentials:
            return  # No passkey data found
        
        # Update passkeys count in statistics
        self.stats["bw_passkeys"] += len(fido2_credentials)
        
        # Store passkey metadata in a separate field
        passkey_metadata_notes = ""
        
        # Process each passkey credential
        for i, credential in enumerate(fido2_credentials):
            # Map Bitwarden fields to KeePassXC/Strongbox format
            
            # 1. Credential ID - store as is
            cred_id = credential.get("credentialId")
            if cred_id:
                field_name = "KPEX_PASSKEY_CREDENTIAL_ID"
                if field_name in (entry.custom_properties or {}):
                    field_name = f"{field_name}_{i+1}"
                entry.set_custom_property(field_name, cred_id, protect=True)
            
            # 2. Relying Party ID (domain)
            rp_id = credential.get("rpId")
            if rp_id:
                field_name = "KPEX_PASSKEY_RELYING_PARTY"
                if field_name in (entry.custom_properties or {}):
                    field_name = f"{field_name}_{i+1}"
                entry.set_custom_property(field_name, rp_id)
            
            # 3. User Handle (base64 encoded binary)
            user_handle = credential.get("userHandle")
            if user_handle:
                field_name = "KPEX_PASSKEY_USER_HANDLE"
                if field_name in (entry.custom_properties or {}):
                    field_name = f"{field_name}_{i+1}"
                entry.set_custom_property(field_name, user_handle, protect=True)
            
            # 4. Username (prefer userName, fall back to userDisplayName)
            username = credential.get("userName")
            if not username:
                username = credential.get("userDisplayName")
            if username:
                field_name = "KPEX_PASSKEY_USERNAME"
                if field_name in (entry.custom_properties or {}):
                    field_name = f"{field_name}_{i+1}"
                entry.set_custom_property(field_name, username)
            
            # 5. Private Key - improved approach with better validation and formatting
            key_value = credential.get("keyValue")
            if key_value:
                try:
                    # Clean the key value - remove all whitespace and line breaks
                    clean_key = ''.join(key_value.split()).replace('-', '+').replace('_', '/') #replacements in case of base64url instead of clean base64
                    
                    # Validate it's proper base64
                    try:
                        # Try to decode to check if it's valid base64
                        base64.b64decode(clean_key)
                        
                        # Format with PEM headers and proper line breaks using textwrap
                        pem_key = (
                            "-----BEGIN PRIVATE KEY-----\n" + 
                            textwrap.fill(clean_key, width=64) + 
                            "\n-----END PRIVATE KEY-----"
                        )
                        
                        # Store PEM in KeePassXC format
                        field_name = "KPEX_PASSKEY_PRIVATE_KEY_PEM"
                        if field_name in (entry.custom_properties or {}):
                            field_name = f"{field_name}_{i+1}"
                        entry.set_custom_property(field_name, pem_key, protect=True)
                        logger.debug(f"Successfully formatted key as PEM")
                    except binascii.Error:
                        logger.warning(f"Key value is not valid base64 for item '{item.get('name')}'")
                        # Store raw value as fallback
                        field_name = "Bitwarden_Raw_KeyValue"
                        if field_name in (entry.custom_properties or {}):
                            field_name = f"{field_name}_{i+1}"
                        entry.set_custom_property(field_name, key_value, protect=True)
                        
                except Exception as e:
                    logger.error(f"Failed to format key as PEM: {str(e)}")
                    # Store the raw key value as a backup
                    field_name = "Bitwarden_Raw_KeyValue"
                    if field_name in (entry.custom_properties or {}):
                        field_name = f"{field_name}_{i+1}"
                    entry.set_custom_property(field_name, key_value, protect=True)
                    logger.info(f"Stored raw key value as backup for item '{item.get('name')}'")
            
            # Store additional passkey fields
            for field_name in ["keyType", "keyAlgorithm", "keyCurve", "rpName", "counter", "discoverable", "creationDate"]:
                value = credential.get(field_name)
                if value:
                    custom_field_name = f"Passkey_{field_name}"
                    if field_name in (entry.custom_properties or {}):
                        custom_field_name = f"{custom_field_name}_{i+1}"
                    entry.set_custom_property(custom_field_name, str(value))
            
            # Collect passkey metadata for a separate notes field
            passkey_metadata_notes += (
                f"Passkey #{i+1}:\n"
                f"Relying Party: {credential.get('rpName', 'Unknown')} ({credential.get('rpId', 'Unknown')})\n"
                f"Key Type: {credential.get('keyType', 'Unknown')}\n"
                f"Algorithm: {credential.get('keyAlgorithm', 'Unknown')}\n"
                f"Curve: {credential.get('keyCurve', 'Unknown')}\n"
                f"Discoverable: {credential.get('discoverable', 'Unknown')}\n"
                f"Creation Date: {credential.get('creationDate', 'Unknown')}\n\n"
            )
            
            # Only process the first credential (Bitwarden typically only allows one per login)
            # But we'll record the presence of more if they exist
            if i == 0 and len(fido2_credentials) > 1:
                logger.warning(f"Item '{item.get('name')}' has multiple passkeys, only the first one was fully processed")
                entry.set_custom_property("Additional_Passkeys_Count", str(len(fido2_credentials) - 1))
            
            # Count successfully added passkey
            self.stats["kp_passkeys"] += 1
            
        # Add detailed passkey metadata as a separate field rather than modifying notes
        if passkey_metadata_notes:
            entry.set_custom_property("Passkey_Metadata", passkey_metadata_notes.strip())

    def add_bitwarden_item(self, item: Dict[str, Any], group: pykeepass.Group) -> None:
        """
        Add a Bitwarden item to KeePass.
        
        Args:
            item: The Bitwarden item data
            group: The KeePass group to add to
        """
        try:
            title = item.get("name") or "Untitled"
            title = self.make_unique_title(group, title)
            item_type = item.get("type")
            notes = item.get("notes") or ""

            # Process based on item type
            if item_type == 1:  # Login
                login = item.get("login", {})
                username = login.get("username") or ""
                password = login.get("password") or ""
                uris = login.get("uris") or []
                url = uris[0].get("uri") if uris and uris[0].get("uri") else ""
                
                entry = self.kp.add_entry(group, title, username, password, url=url, notes=notes)
                
                # Handle additional URIs as custom properties
                if len(uris) > 1:
                    for idx, uri_obj in enumerate(uris[1:], start=2):
                        uri_val = uri_obj.get("uri")
                        match_type = uri_obj.get("match")
                        if uri_val:
                            entry.set_custom_property(f"URL {idx}", uri_val)
                            if match_type is not None:
                                match_names = {
                                    0: "Base Domain",
                                    1: "Host",
                                    2: "Starts With",
                                    3: "Exact",
                                    4: "Regular Expression",
                                    5: "Never"
                                }
                                match_name = match_names.get(match_type, str(match_type))
                                entry.set_custom_property(f"URL {idx} Match", match_name)

                # Handle TOTP - support multiple plugin formats
                totp = login.get("totp")
                if totp:
                    totp = totp.replace(" ", "").upper()

                    # Increment Bitwarden TOTP counter
                    self.stats["bw_totp"] += 1

                    # For KeePass built-in TOTP
                    entry.set_custom_property("TimeOtp-Secret-Base32", totp, protect=True)

                    # For KeePassXC compatibility
                    entry.set_custom_property("TOTP Seed", totp, protect=True)
                    entry.set_custom_property("TOTP Settings", "30;6")

                    # For KeeOtp plugin
                    entry.otp = "otpauth://totp/?secret=" + totp

                    # Increment KeePass TOTP counter
                    self.stats["kp_totp"] += 1

                    logger.debug(f"Added TOTP for item '{title}'")


            elif item_type == 2:  # Secure Note
                entry = self.kp.add_entry(group, title, "", "", notes=notes)
                entry.set_custom_property("Secure Note Type", str(item.get("secureNote", {}).get("type", 0)))
                
            elif item_type == 3:  # Card
                card = item.get("card", {})
                cardholder_name = card.get("cardholderName") or ""
                brand = card.get("brand") or ""
                number = card.get("number") or ""
                exp_month = card.get("expMonth") or ""
                exp_year = card.get("expYear") or ""
                code = card.get("code") or ""
                
                entry = self.kp.add_entry(group, title, "", "", notes=notes)
                entry.set_custom_property("Cardholder Name", cardholder_name)
                entry.set_custom_property("Brand", brand)
                entry.set_custom_property("Number", number)
                entry.set_custom_property("Expiration Month", str(exp_month))
                entry.set_custom_property("Expiration Year", str(exp_year))
                
                if code:
                    entry.set_custom_property("Security Code", code, protect=True)

            elif item_type == 4:  # Identity
                identity = item.get("identity", {})
                entry = self.kp.add_entry(group, title, identity.get("username") or "", "", notes=notes)
                for key, label in [
                    ("title", "Title"),
                    ("firstName", "First Name"),
                    ("middleName", "Middle Name"),
                    ("lastName", "Last Name"),
                    ("address1", "Address Line 1"),
                    ("address2", "Address Line 2"),
                    ("address3", "Address Line 3"),
                    ("city", "City"),
                    ("state", "State/Province"),
                    ("postalCode", "Postal Code"),
                    ("country", "Country"),
                    ("company", "Company"),
                    ("email", "Email"),
                    ("phone", "Phone"),
                    ("ssn", "SSN"),
                    ("passportNumber", "Passport Number"),
                    ("licenseNumber", "License Number")
                ]:
                    if value := identity.get(key) or "":
                        protect = key in ["ssn", "passportNumber", "licenseNumber"]
                        # noinspection PyUnboundLocalVariable
                        entry.set_custom_property(label, value, protect=protect)

            elif item_type == 5:  # SSH Key
                ssh_key = item.get("sshKey", {})
                private_key = ssh_key.get("privateKey") or ""
                public_key = ssh_key.get("publicKey") or ""
                key_fingerprint = ssh_key.get("keyFingerprint") or ""
                
                # Track SSH Keys in statistics
                self.stats["bw_ssh_keys"] += 1
                
                entry = self.kp.add_entry(group, title, "", "", notes=notes)
                
                # Store SSH key fields with appropriate protection
                if private_key:
                    entry.set_custom_property("Private Key", private_key, protect=True)
                if public_key:
                    entry.set_custom_property("Public Key", public_key)
                if key_fingerprint:
                    entry.set_custom_property("Key Fingerprint", key_fingerprint)
                
                # Track successful SSH key conversion
                self.stats["kp_ssh_keys"] += 1
                
            else:
                entry = self.kp.add_entry(group, title, "", "", notes=notes)
                entry.set_custom_property("Item Type", str(item_type))
            
            # Add custom fields with duplicate handling
            if entry and item.get("fields"):
                custom_fields_added = self._add_custom_fields(entry, item.get("fields"))
                logger.debug(f"Added {custom_fields_added} custom fields to item '{title}'")
                    
            # Add passkey data
            if entry and item_type == 1:  # Only extract passkeys for login items
                self.extract_and_add_passkey_data(item, entry)
      
            
            # Add attachments with comprehensive validation and error handling
            if entry:  # Check that entry is not None
                attachments_added = 0
                for att in item.get("attachments") or []:
                    att_id = att.get("id")
                    att_filename = att.get("fileName")
                    
                    # Basic validation - skip if no ID or filename
                    if not att_id or not att_filename:
                        logger.debug(f"Skipping unnamed or invalid attachment in item '{title}'")
                        continue
                        
                    # Sanitize filename - replace invalid characters
                    invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0']
                    if any(c in att_filename for c in invalid_chars):
                        safe_filename = ''.join(c if c not in invalid_chars else '_' for c in att_filename)
                        logger.warning(f"Sanitized invalid characters in filename: '{att_filename}' → '{safe_filename}'")
                        att_filename = safe_filename
                    
                    try:
                        # Download attachment data
                        data = self.bw.get_attachment(att_id, item.get("id"))
                        
                        # Check for empty data
                        if not data or len(data) == 0:
                            logger.warning(f"Empty attachment data for '{att_filename}' in item '{title}' - skipping")
                            continue
                            
                        # Ensure unique filename within this entry
                        existing_attachments = [a.filename for a in entry.attachments]
                        if att_filename in existing_attachments:
                            base, ext = os.path.splitext(att_filename)
                            counter = 1
                            while f"{base}_{counter}{ext}" in existing_attachments:
                                counter += 1
                            logger.debug(f"Renamed duplicate attachment: '{att_filename}' → '{base}_{counter}{ext}'")
                            att_filename = f"{base}_{counter}{ext}"
                        
                        # Add binary and attachment
                        binary_id = self.kp.add_binary(data)
                        if binary_id is None:  # Check for None explicitly instead of falsy value
                            logger.warning(f"Failed to get binary ID for '{att_filename}' in item '{title}' - skipping")
                            continue
                            
                        entry.add_attachment(binary_id, att_filename)
                        attachments_added += 1
                        
                        logger.debug(f"Added attachment '{att_filename}' from item '{title}' (size: {len(data)} bytes)")
                    except Exception as e:
                        logger.error(f"Failed to add attachment '{att_filename}': {str(e)}")
                        self.stats["errors"] += 1
                
                # Update attachment statistics with only successfully added ones
                if attachments_added > 0:
                    self.stats["kp_attachments"] += attachments_added
            
        except Exception as e:
            logger.error(f"Failed to add item '{item.get('name', 'Unknown')}': {str(e)}")
            self.stats["errors"] += 1

    def process_items(self) -> None:
        """Process all items from Bitwarden and add them to KeePass."""
        try:
            item_list_raw = self.bw.list_items()
            items = json.loads(item_list_raw)

            # Filter items by date if date_since is provided
            if self.date_since:
                try:
                    # Parse the date_since string to a datetime object
                    filter_date = datetime.strptime(self.date_since, "%Y-%m-%d").replace(
                        hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc
                    )

                    # Count total items before filtering
                    total_items = len(items)

                    # Filter items where revisionDate >= date_since
                    filtered_items = []
                    for item in items:
                        revision_date_str = item.get("revisionDate")
                        if revision_date_str:
                            # Bitwarden uses ISO format dates
                            revision_date = datetime.fromisoformat(revision_date_str.replace("Z", "+00:00"))
                            if revision_date >= filter_date:
                                filtered_items.append(item)

                    # Update statistics
                    self.stats["skipped_items"] = total_items - len(filtered_items)
                    items = filtered_items

                    logger.info(
                        f"Filtered items by date: processing {len(items)} items modified on or after {self.date_since} "
                        f"(skipped {self.stats['skipped_items']} older items)")
                except ValueError as e:
                    logger.error(f"Invalid date format for --date-since: {str(e)}. Use YYYY-MM-DD format.")
                    sys.exit(1)

            self.stats["bw_items"] = len(items)
            self.stats["bw_attachments"] = sum(len(i.get('attachments') or []) for i in items)

            logger.info(f"Processing {self.stats['bw_items']} items with {self.stats['bw_attachments']} attachments")

            # Process in batches
            for i in range(0, len(items), self.batch_size):
                batch = items[i:i + self.batch_size]
                logger.info(
                    f"Processing batch {i // self.batch_size + 1}/{(len(items) + self.batch_size - 1) // self.batch_size}")

                for item in batch:
                    folder_id = item.get("folderId")
                    folder_entry = self.folders_dict.get(folder_id)

                    if folder_entry is None or folder_entry.get("name", "").strip().lower() == "no folder":
                        group = self.kp.root_group
                    else:
                        folder_parts = folder_entry.get("split", [])
                        group = self.get_or_create_group(folder_parts)

                    self.add_bitwarden_item(item, group)

                # Save progress after each batch
                self.kp.save()
                logger.info(f"Saved progress after batch {i // self.batch_size + 1}")

            # Save final statistics
            self.stats["kp_entries"] = len(self.kp.entries)
            self.stats["kp_attachments"] = len(self.kp.attachments)
            self.stats["kp_groups"] = sum(1 for _ in self.kp.groups)

        except Exception as e:
            logger.error(f"Failed to process items: {str(e)}")
            # Try to save what we have so far
            if self.kp:
                self.kp.save()
            sys.exit(1)

    def finalize(self) -> None:
        """Finalize the export and clean up."""
        try:
            self.kp.save()
            logger.info(f"Saved KeePass database to {self.output_path}")

            # Log statistics
            logger.info(f"Bitwarden: {self.stats['bw_folders']} folders, "
                        f"{self.stats['bw_items']} items, "
                        f"{self.stats['bw_attachments']} attachments, "
                        f"{self.stats['bw_passkeys']} passkeys, "
                        f"{self.stats['bw_ssh_keys']} SSH keys, "
                        f"{self.stats['bw_totp']} TOTP codes")

            logger.info(f"KeePass: {self.stats['kp_groups']} groups, "
                        f"{self.stats['kp_entries']} entries, "
                        f"{self.stats['kp_attachments']} attachments, "
                        f"{self.stats['kp_passkeys']} passkeys, "
                        f"{self.stats['kp_ssh_keys']} SSH keys, "
                        f"{self.stats['kp_totp']} TOTP codes")

            if self.stats["errors"] > 0:
                logger.warning(f"Completed with {self.stats['errors']} errors")
            else:
                logger.info("Export completed successfully")

            # Logout from Bitwarden
            if self.bw:
                self.bw.logout()

        except Exception as e:
            logger.error(f"Failed to finalize export: {str(e)}")
            sys.exit(1)

    def run(self) -> None:
        """Run the complete export process."""
        self.connect_bitwarden()
        self.setup_keepass()
        self.process_folders()
        self.process_items()
        self.finalize()


def main():
    """Parse arguments and run the exporter."""
    parser = argparse.ArgumentParser(description="Export Bitwarden vault to KeePass")
    parser.add_argument("-o", "--output", help="Output KeePass file path")
    parser.add_argument("-k", "--keyfile", help="Create and use a KeePass keyfile")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("-b", "--batch-size", type=int, default=100,
                        help="Number of items to process in one batch")
    parser.add_argument("--bw-path", help="Custom path to Bitwarden CLI executable")
    parser.add_argument("--date-since", help="Process only items modified on or after this date (YYYY-MM-DD)")
    args = parser.parse_args()

    exporter = Bitwarden2KeePassExporter(
        output_path=args.output,
        keyfile_path=args.keyfile,
        debug=args.debug,
        batch_size=args.batch_size,
        bw_path=args.bw_path,
        date_since=args.date_since
    )
    exporter.run()


if __name__ == "__main__":
    main()
"""
Enhanced Bitwarden CLI wrapper with improved error handling,
caching, and platform independence.
"""

import subprocess
import urllib.request
import zipfile
import io
import os
import platform
import tempfile
import shutil
import getpass
import logging
import time
import json
import random
from typing import Optional, Dict, Any, Union, List, Tuple

# Set up logging
logger = logging.getLogger(__name__)


class BwSession:
    """
    Bitwarden CLI wrapper with platform detection and enhanced features.
    
    - Auto-detects platform and downloads appropriate CLI binary
    - Manages session-based authentication
    - Handles caching for improved performance
    - Adds comprehensive error handling
    """

    # Platform-specific download URLs and executables
    PLATFORM_INFO = {
        "Windows": {
            "url": "https://vault.bitwarden.com/download/?app=cli&platform=windows",
            "filename": "bw.exe",
        },
        "Darwin": {  # macOS
            "url": "https://vault.bitwarden.com/download/?app=cli&platform=macos",
            "filename": "bw",
        },
        "Linux": {
            "url": "https://vault.bitwarden.com/download/?app=cli&platform=linux",
            "filename": "bw",
        },
    }
    
    # Cache timeouts (seconds)
    CACHE_TIMEOUT = {
        "items": 300,  # 5 minutes
        "folders": 300,
    }

    def __init__(self, cache_dir: Optional[str] = None, cli_path: Optional[str] = None):
        """
        Initialize the Bitwarden session.
        
        Args:
            cache_dir: Directory to store cache files (defaults to temp directory)
            cli_path: Custom path to bw CLI executable (will skip download if provided)
        """
        self.platform = platform.system()
        if self.platform not in self.PLATFORM_INFO:
            raise RuntimeError(f"Unsupported platform: {self.platform}")
            
        # Set up paths
        platform_info = self.PLATFORM_INFO[self.platform]
        self.bw_filename = platform_info["filename"]
        
        # Store the provided CLI path if any
        self.custom_cli_path = cli_path
        
        # The actual path will be determined by _ensure_bw_cli
        self.bw_path = None
            
        # Set up cache
        self.cache_dir = cache_dir or os.path.join(tempfile.gettempdir(), "bw_session_cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.cache = {}
        
        # Session info
        self.session: Optional[str] = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.login_time: Optional[float] = None
        self.status: Dict[str, Any] = {}
        
        # Ensure CLI is available
        self._ensure_bw_cli()

    def _find_bw_in_path(self) -> Optional[str]:
        """
        Find the Bitwarden CLI in system PATH.
        
        Returns:
            Full path to the bw executable if found, None otherwise
        """
        try:
            # Use 'where' on Windows and 'which' on Unix-like systems
            cmd = 'where' if self.platform == 'Windows' else 'which'
            result = subprocess.run([cmd, self.bw_filename], capture_output=True, text=True)
            
            if result.returncode == 0:
                # Return the first path if multiple are found
                path = result.stdout.strip().split('\n')[0]
                logger.info(f"Found Bitwarden CLI in PATH: {path}")
                return path
        except Exception as e:
            logger.debug(f"Couldn't find Bitwarden CLI in PATH: {str(e)}")
        
        return None

    @staticmethod
    def _verify_bw_cli(path: str) -> bool:
        """
        Verify that the Bitwarden CLI at the given path works.
        
        Args:
            path: Path to the bw executable
            
        Returns:
            True if the CLI works, False otherwise
        """
        try:
            version = subprocess.run(
                [path, "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            ).stdout.strip()
            logger.info(f"Found Bitwarden CLI version: {version}")
            return True
        except Exception as e:
            logger.warning(f"Bitwarden CLI at {path} is not working: {str(e)}")
            return False

    def _ensure_bw_cli(self) -> None:
        """Download and set up the Bitwarden CLI if not already available."""
        # 1. Check if a custom path was provided
        if self.custom_cli_path and os.path.exists(self.custom_cli_path):
            if self._verify_bw_cli(self.custom_cli_path):
                self.bw_path = self.custom_cli_path
                return
            logger.warning(f"Custom CLI path {self.custom_cli_path} is invalid, will try alternatives")
        
        # 2. Check if bw is in PATH
        path_bw = self._find_bw_in_path()
        if path_bw and self._verify_bw_cli(path_bw):
            self.bw_path = path_bw
            return
        
        # 3. Check if bw is in current directory
        local_bw = os.path.join(os.getcwd(), self.bw_filename)
        if os.path.exists(local_bw) and self._verify_bw_cli(local_bw):
            self.bw_path = local_bw
            return
        
        # 4. Download a new copy
        platform_info = self.PLATFORM_INFO[self.platform]
        logger.info(f"Downloading Bitwarden CLI for {self.platform}...")
        
        try:
            response = urllib.request.urlopen(platform_info["url"])
            zip_data = response.read()
            
            with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
                z.extract(self.bw_filename, path=os.getcwd())
                
            self.bw_path = os.path.join(os.getcwd(), self.bw_filename)
                
            if self.platform != "Windows":
                # Make executable on Unix-like systems
                os.chmod(self.bw_path, 0o755)
                
            logger.info(f"Downloaded and extracted {self.bw_filename}")
            
            # Verify the binary works
            if not self._verify_bw_cli(self.bw_path):
                raise RuntimeError("Downloaded Bitwarden CLI doesn't work")
            
        except Exception as e:
            raise RuntimeError(f"Failed to set up Bitwarden CLI: {str(e)}") from e

    def check_status(self) -> Dict[str, Any]:
        """
        Check current Bitwarden login status.
        
        Returns:
            Dict with status information
        """
        try:
            result = subprocess.run(
                [self.bw_path, 'status'], 
                capture_output=True, 
                text=True
            )
            if result.returncode == 0:
                self.status = json.loads(result.stdout)
                return self.status
            return {"status": "error", "error": result.stderr.strip()}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def login(self, username: Optional[str] = None, password: Optional[str] = None,
              totp: Optional[str] = None, force: bool = False) -> bool:
        """
        Log in to Bitwarden.

        Args:
            username: Bitwarden email (will prompt if None)
            password: Master password (will prompt if None)
            totp: TOTP code for 2FA (will prompt if needed and None)
            force: Force new login even if already logged in

        Returns:
            True if login was successful
        """
        # Check if we already have a valid session
        if not force and self.session:
            status = self.check_status()
            if status.get("status") in ["unlocked", "locked"]:
                logger.info(f"Already logged in with status: {status.get('status')}")
                return True

        # Get current status if we haven't already
        if not hasattr(self, '_status'):
            status = self.check_status()

        # If vault is locked, just unlock it to get a session key
        if status.get("status") == "locked":
            logger.info("Vault is locked. Using unlock to get session key.")
            # Get password if not provided
            self.password = password or getpass.getpass("Master password: ")
            return self.unlock()

        try:
            # Use provided credentials or prompt
            self.username = username or input("Bitwarden email: ").strip()
            self.password = password or getpass.getpass("Master password: ")

            login_cmd = [self.bw_path, 'login', '--raw']

            # Handle 2FA if needed
            if totp:
                login_cmd += ['--method', '0', '--code', totp]
            else:
                # Only prompt for TOTP if needed
                user_totp = input("TOTP code (leave blank if not using 2FA): ").strip()
                if user_totp:
                    login_cmd += ['--method', '0', '--code', user_totp]

            login_cmd += [self.username, self.password]

            result = subprocess.run(login_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                # Check if the error is because we're already logged in
                if "You are already logged in" in result.stderr:
                    logger.info("Already logged in, retrieving session key via unlock...")
                    return self.unlock()

                logger.error(f"Login failed: {result.stderr.strip()}")
                return False

            self.session = result.stdout.strip()
            self.login_time = time.time()
            logger.info("Login successful. Session key acquired.")

            # Clear any existing cache after login
            self._clear_cache()

            return True

        except Exception as e:
            logger.error(f"Login failed with exception: {str(e)}")
            return False

    def unlock(self) -> bool:
        """
        Unlock the Bitwarden vault.

        Returns:
            True if unlock was successful
        """
        if self.session and self.check_status().get("status") == "unlocked":
            return True

        try:
            if not self.password:
                self.password = getpass.getpass("Master password: ")

            result = subprocess.run(
                [self.bw_path, 'unlock', '--raw'],
                input=self.password,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.error(f"Unlock failed: {result.stderr.strip()}")
                return False

            self.session = result.stdout.strip()
            logger.info("Vault unlocked. Session key retrieved.")
            return True

        except Exception as e:
            logger.error(f"Unlock failed with exception: {str(e)}")
            return False

    def _clear_cache(self, item_type: Optional[str] = None) -> None:
        """
        Clear the cache.

        Args:
            item_type: Specific item type to clear or None for all
        """
        if item_type:
            if item_type in self.cache:
                del self.cache[item_type]
                cache_file = os.path.join(self.cache_dir, f"{item_type}.json")
                if os.path.exists(cache_file):
                    os.remove(cache_file)
        else:
            self.cache = {}
            for file in os.listdir(self.cache_dir):
                if file.endswith(".json"):
                    os.remove(os.path.join(self.cache_dir, file))

    def _check_cache(self, item_type: str) -> Tuple[bool, Any]:
        """
        Check if valid cached data exists.

        Args:
            item_type: Type of item to check

        Returns:
            Tuple with (is_valid, data)
        """
        # Check memory cache first
        if item_type in self.cache:
            cache_time, data = self.cache[item_type]
            if time.time() - cache_time < self.CACHE_TIMEOUT.get(item_type, 300):
                return True, data

        # Check file cache
        cache_file = os.path.join(self.cache_dir, f"{item_type}.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)

                if time.time() - cache_data.get("time", 0) < self.CACHE_TIMEOUT.get(item_type, 300):
                    # Update memory cache
                    data = cache_data.get("data")
                    self.cache[item_type] = (cache_data.get("time"), data)
                    return True, data
            except Exception as e:
                logger.debug(f"Error reading cache file: {str(e)}")

        return False, None

    def _save_cache(self, item_type: str, data: Any) -> None:
        """
        Save data to cache.

        Args:
            item_type: Type of item to save
            data: Data to cache
        """
        current_time = time.time()
        self.cache[item_type] = (current_time, data)

        # Save to file cache
        cache_file = os.path.join(self.cache_dir, f"{item_type}.json")
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "time": current_time,
                    "data": data
                }, f, ensure_ascii=False)
        except Exception as e:
            logger.debug(f"Error saving cache file: {str(e)}")

    def _exec(self, args: list, input_data: Optional[str] = None,
             binary: bool = False, use_cache: bool = True) -> Union[Optional[str], Any]:
        """
        Execute a Bitwarden CLI command.

        Args:
            args: Command arguments
            input_data: Optional input data
            binary: Whether to return binary data
            use_cache: Whether to use caching (for list commands)

        Returns:
            Command output as string or bytes
        """
        # Check if we should use cache
        if use_cache and args[0] == 'list':
            cache_key = f"{args[0]}_{args[1]}"
            is_valid, data = self._check_cache(cache_key)
            if is_valid:
                logger.debug(f"Using cached data for {cache_key}")
                return data

        # Ensure we're unlocked
        # Improved logic:
        status = self.check_status()
        if status.get("status") == "unauthenticated":
            if not self.login():
                raise RuntimeError("Authentication required")
        # Remove the "locked" check since commands work with --session even when locked


        cmd = [self.bw_path] + args
        if self.session:
            cmd += ['--session', self.session]

        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                result = subprocess.run(
                    cmd,
                    input=input_data,
                    capture_output=True,
                    text=not binary,
                    encoding=None if binary else 'utf-8'
                )

                if result.returncode != 0:
                    err = result.stderr if binary else result.stderr.strip()
                    error_msg = err.decode('utf-8', errors='replace') if binary else err

                    # Check if session expired
                    if "session" in error_msg.lower() and "expire" in error_msg.lower() and attempt < max_retries:
                        logger.info("Session expired. Attempting to login again...")
                        self.login()
                        continue

                    raise RuntimeError(f"Command failed: {error_msg}")

                output = result.stdout if binary else result.stdout.strip()

                # Cache the result if appropriate
                if use_cache and args[0] == 'list' and not binary:
                    cache_key = f"{args[0]}_{args[1]}"
                    self._save_cache(cache_key, output)

                return output

            except Exception as e:
                if attempt < max_retries:
                    logger.info(f"Retrying command after error: {str(e)}")
                    time.sleep(1)  # Brief pause before retry
                    return None
                else:
                    raise RuntimeError(f"Command failed after {max_retries + 1} attempts: {str(e)}")
        return None

    def sync(self) -> str:
        """
        Sync the Bitwarden vault.

        Returns:
            Sync status message
        """
        result = self._exec(['sync'], use_cache=False)
        # Clear cache after sync
        self._clear_cache()
        return result

    def list_items(self, force_refresh: bool = False) -> str:
        """
        List all vault items.

        Args:
            force_refresh: Force refresh ignoring cache

        Returns:
            JSON string of all items
        """
        return self._exec(['list', 'items'], use_cache=not force_refresh)

    def list_folders(self, force_refresh: bool = False) -> str:
        """
        List all folders.

        Args:
            force_refresh: Force refresh ignoring cache

        Returns:
            JSON string of all folders
        """
        return self._exec(['list', 'folders'], use_cache=not force_refresh)

    def get_item(self, item_id: str) -> str:
        """
        Get a specific item.

        Args:
            item_id: Item ID

        Returns:
            JSON string of the item
        """
        return self._exec(['get', 'item', item_id])

    def get_password(self, item_id: str) -> str:
        """
        Get an item's password.

        Args:
            item_id: Item ID

        Returns:
            Password string
        """
        return self._exec(['get', 'password', item_id])


    def get_attachment(self, attachment_id: str, item_id: str, retry_attempts: int = 3,
                     retry_delay: float = 5.0) -> Optional[bytes]:
        """
        Download an attachment using _exec for command execution within a retry loop.

        Args:
            attachment_id: Attachment ID
            item_id: Item ID
            retry_attempts: Number of retry attempts (default: 3)
            retry_delay: Initial delay between retries in seconds (default: 5.0)

        Returns:
            Binary attachment data
        """
        # Use a context manager for safer temporary file handling
        with tempfile.TemporaryDirectory(prefix="bw_attachments_") as temp_dir:
            # Generate a temporary unique filename within the temp directory
            # Using NamedTemporaryFile might seem intuitive, but bw writes to the path,
            # so we need a persistent path during the _exec call.
            temp_file_handle, filepath = tempfile.mkstemp(dir=temp_dir, suffix=".tmp")
            os.close(temp_file_handle) # Close handle, we just need the path

            try:
                # Retry loop from the original method
                for attempt in range(retry_attempts + 1): # +1 for initial attempt
                    try:
                        # Construct args for _exec
                        args = [
                            'get', 'attachment', attachment_id,
                            '--itemid', item_id,
                            '--output', filepath
                        ]

                        # Execute using _exec.
                        # - use_cache=False: Attachment downloads shouldn't be cached.
                        # - binary=False: _exec doesn't need to handle binary output itself,
                        #   as the command writes to a file. We just need success/failure.
                        # _exec will handle session checks, unlocking, and basic retries (like session expiry) internally.
                        # We might want to add a timeout parameter to _exec if it doesn't have one,
                        # or rely on the subprocess timeout within _exec if it's sufficient.
                        # For now, assuming _exec handles basic execution and session errors.
                        self._exec(args, use_cache=False)

                        # If _exec succeeded, check the output file
                        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
                            # This might indicate an issue even if _exec reported success (e.g., bw bug)
                            raise RuntimeError(f"Attachment download via _exec produced an empty or missing file: {filepath}")

                        # Read the binary data from the temporary file
                        with open(filepath, 'rb') as f:
                            data = f.read()

                        logger.debug(f"Downloaded attachment ID '{attachment_id}' from item ID '{item_id}' (attempt {attempt+1}/{retry_attempts+1})")
                        return data # Success! Exit the loop and return data.

                    except (subprocess.TimeoutExpired, TimeoutError) as e:
                        # Catch specific timeout errors potentially raised by _exec or its subprocess call
                        last_error = f"Timeout error: {str(e)}"
                        logger.warning(f"Attachment download timed out (attempt {attempt+1}/{retry_attempts+1}): {attachment_id}")
                        # Let the retry logic below handle it

                    except RuntimeError as e:
                        # Catch errors raised by _exec (like command failure after its internal retries)
                        # or errors we raised (like empty file check).
                        error_msg = str(e)
                        last_error = error_msg

                        # _exec handles session state internally. If it raises a RuntimeError
                        # due to session issues, it means its internal fix attempt failed.
                        # We don't retry specifically for session errors here.

                        # Check for potentially transient network errors during the command execution
                        # that might warrant a retry with backoff.
                        # Note: Timeouts are handled in their specific except block above.
                        if any(err_type in error_msg.lower() for err_type in ["etimedout", "network", "connection"]):
                            logger.warning(f"Potential Network/Connection error detected (attempt {attempt+1}/{retry_attempts+1}): {error_msg}")
                            # Fall through to the retry delay logic below
                        # Check for our specific error when the downloaded file is empty/missing
                        elif "produced an empty or missing file" in error_msg:
                             logger.warning(f"Empty/missing file detected after download (attempt {attempt+1}/{retry_attempts+1}): {error_msg}")
                             # Fall through to the retry delay logic below (maybe it was a transient issue)
                        else:
                            # For other RuntimeErrors (including unresolved session issues from _exec,
                            # command errors, etc.), don't retry, raise immediately.
                            logger.error(f"Non-retryable runtime error during attachment download: {error_msg}")
                            raise RuntimeError(f"Failed to download attachment '{attachment_id}': {error_msg}") from e

                    except Exception as e:
                        # Catch any other unexpected exceptions
                        last_error = str(e)
                        logger.warning(f"Unexpected error during attachment download (attempt {attempt+1}/{retry_attempts+1}): {str(e)}")
                        # Let the retry logic below handle it, but consider if this should raise immediately

                    # --- Retry Delay Logic ---
                    # Don't sleep on the last attempt
                    if attempt < retry_attempts:
                        # Exponential backoff with jitter
                        current_delay = retry_delay * (1.5 ** attempt) * (0.9 + 0.2 * random.random())
                        logger.info(f"Retrying attachment download in {current_delay:.1f} seconds...")
                        time.sleep(current_delay)
                    else:
                         # If loop finishes, all attempts failed
                         raise RuntimeError(f"Failed to download attachment '{attachment_id}' after {retry_attempts+1} attempts. Last error: {last_error}")

            finally:
                # Ensure the temporary file is always cleaned up, even if created outside the loop scope initially
                if os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                    except OSError as cleanup_error:
                        logger.warning(f"Could not remove temporary attachment file {filepath}: {cleanup_error}")

        # The temporary directory created by TemporaryDirectory is automatically cleaned up here.
    def logout(self) -> bool:
        """
        Log out from Bitwarden.

        Returns:
            True if successfully logged out
        """
        try:
            self._exec(['logout'], use_cache=False)
            self.session = None
            self.password = None
            self._clear_cache()
            logger.info("Logged out successfully")
            return True
        except Exception as e:
            logger.error(f"Logout failed: {str(e)}")
            return False

    @property
    def cli_path(self) -> str:
        """
        Get the path to the Bitwarden CLI executable.

        Returns:
            The path to the Bitwarden CLI executable
        """
        return self.bw_path

    def __del__(self):
        """Clean up on deletion."""
        # Try to remove cache files
        try:
            self._clear_cache()
            if os.path.exists(self.cache_dir) and not os.listdir(self.cache_dir):
                os.rmdir(self.cache_dir)
        except:
            pass
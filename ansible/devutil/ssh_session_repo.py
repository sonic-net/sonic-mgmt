"""
This file contains the utility classes to generate SSH session repository.

Currently, we support generating the SSH session repository for SecureCRT.
"""

import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


class SshSessionRepoGenerator(object):
    """Base class for ssh session repo generator."""

    def __init__(self, target, template_file):
        """Store all parameters as attributes.

        Args:
            target (str): Output target.
            template_file (str): SSH session template file.
        """
        self.target = target
        self.template = self._load_template(template_file)

    def _load_template(self, template_file):
        """Load SSH session template file.

        Args:
            template_file (str): SSH session template file.

        Returns:
            str: SSH session template file content.
        """
        raise NotImplementedError

    def generate(self, session_path, ssh_ip, ssh_user, ssh_pass):
        """Generate SSH session for a node.

        This is a virtual method that should be implemented by child class.

        Args:
            testbed (object): Represents a testbed setup.
            testbed_node (object): Represents a connectable node in the testbed.
        """
        raise NotImplementedError


class SecureCRTSshSessionRepoGenerator(SshSessionRepoGenerator):
    """SSH session repo generator for SecureCRT.

    It derives from SshSessionRepoGenerator and implements the generate method.
    """

    def __init__(self, target, template_file):
        super().__init__(target, template_file)
        self.crypto = SecureCRTCryptoV2()

    def _load_template(self, template_file):
        """Load SSH session template file.

        Args:
            template_file (str): SSH session template file.

        Returns:
            str: SSH session template file content.
        """
        if template_file is None:
            raise ValueError("SSH session template file is not specified.")

        if not os.path.isfile(template_file):
            raise ValueError(
                "SSH session template file {} does not exist.".format(template_file)
            )

        template = ""
        with open(template_file, "r", encoding="utf-8-sig") as f:
            for line in f:
                if line.startswith('S:"Username"='):
                    template += 'S:"Username"=%USERNAME%\n'
                    continue
                elif line.startswith('S:"Hostname"='):
                    template += 'S:"Hostname"=%HOST%\n'
                    continue
                elif line.startswith('S:"Password V2"='):
                    template += 'S:"Password V2"=%PASSWORD%\n'
                    continue
                elif line.startswith('S:"SSH2 Authentications V2"='):
                    template += 'S:"SSH2 Authentications V2"=password,publickey,keyboard-interactive,gssapi\n'
                    continue
                else:
                    template += line

            return template

    def generate(self, session_path, ssh_ip, ssh_user, ssh_pass):
        """Generate SSH session for a testbed node."""
        # In SecureCRT, every SSH session is stored in a ini file separately,
        # hence we add .ini extension to the session path in order to generate individual SSH session file.
        ssh_session_file_path = os.path.join(self.target, session_path + ".ini")

        # Recursively create SSH session file directory
        ssh_session_folder = os.path.dirname(ssh_session_file_path)
        self._create_ssh_session_folder(ssh_session_folder)

        # Generate SSH session file
        ssh_session_name = os.path.basename(session_path)
        ssh_session_file_content = self._generate_ssh_session_file_content(
            ssh_session_name, ssh_ip, ssh_user, ssh_pass
        )
        with open(ssh_session_file_path, "w") as ssh_session_file:
            ssh_session_file.write(ssh_session_file_content)

        # Add newly created session file into current folder data
        ssh_session_folder_data = SecureCRTRepoFolderData.from_folder(
            ssh_session_folder, create_if_not_exist=True
        )
        ssh_session_folder_data.add_session(ssh_session_name)
        ssh_session_folder_data.save()

    def _create_ssh_session_folder(self, ssh_session_file_dir):
        """Recursively create SSH session file directory level by level if it does not exist,
        and init the folder with a folder data ini file.

        Args:
            ssh_session_file_dir (str): SSH session file folder.
        """
        if os.path.exists(ssh_session_file_dir):
            return

        # Recursively create parent folder
        parent_ssh_session_file_dir = os.path.dirname(ssh_session_file_dir)
        if not os.path.exists(parent_ssh_session_file_dir):
            self._create_ssh_session_folder(parent_ssh_session_file_dir)

        # Create current folder
        os.mkdir(ssh_session_file_dir)

        # Add current folder to parent folder data, since it is newly created
        parent_folder_data = SecureCRTRepoFolderData.from_folder(
            parent_ssh_session_file_dir, create_if_not_exist=True
        )
        parent_folder_data.add_folder(os.path.basename(ssh_session_file_dir))
        parent_folder_data.save()

    def _generate_ssh_session_file_content(
        self, session_name, ssh_ip, ssh_user, ssh_pass
    ):
        """Generate SSH session file content:

        Args:
            session_path (str): SSH session file path.
            ssh_ip (str): SSH IP address.
            ssh_user (str): SSH username.
            ssh_pass (str): SSH password.

        Returns:
            str: SSH session file content.
        """
        encrypted_pass = "02:" + self.crypto.encrypt(ssh_pass)
        return (
            self.template.replace("%USERNAME%", ssh_user)
            .replace("%HOST%", ssh_ip)
            .replace("%PASSWORD%", encrypted_pass)
        )


class SecureCRTRepoFolderData(object):
    """This class represents the __FolderData__.ini file in SecureCRT SSH session repository."""

    @classmethod
    def from_folder(cls, folder, create_if_not_exist=False):
        """Create a SecureCRTRepoFolderData object from a folder.

        Args:
            folder (str): Folder name.
            create_if_not_exist (bool, optional): Create the folder if it does not exist. Defaults to False.

        Returns:
            SecureCRTRepoFolderData: SecureCRTRepoFolderData object.
        """
        ini_path = os.path.join(folder, "__FolderData__.ini")
        if not os.path.exists(ini_path):
            if create_if_not_exist:
                with open(ini_path, "w") as ini_file:
                    ini_file.write('S:"Folder List"=\r\n')
                    ini_file.write('S:"Session List"=\r\n')
                    ini_file.write('S:"Is Expanded"=00000000\r\n')
            else:
                return None

        return cls(folder, ini_path)

    def __init__(self, folder, ini_path):
        """Init SecureCRTRepoFolderData object.

        Args:
            ini_path (str): __FolderData__.ini file path.
        """
        self.folder = folder
        self.ini_path = ini_path

        self.folder_list = []
        self.session_list = []
        self.is_expanded = False

        self._parse_ini_file()

    def _parse_ini_file(self):
        if not os.path.exists(self.ini_path):
            return

        with open(self.ini_path, "r") as ini_file:
            for line in ini_file:
                if line.startswith('S:"Folder List"='):
                    self.folder_list = set(
                        [e for e in line.split("=")[1].strip().split(":") if e]
                    )
                elif line.startswith('S:"Session List"='):
                    self.session_list = set(
                        [e for e in line.split("=")[1].strip().split(":") if e]
                    )
                elif line.startswith('S:"Is Expanded"='):
                    self.is_expanded = bool(int(line.split("=")[1].strip()))

    def add_folder(self, folder):
        """Add a folder to the folder list.

        Args:
            folder (str): Folder name.
        """
        self.folder_list.add(folder)

    def add_session(self, session):
        """Add a session to the session list.

        Args:
            session (str): Session name.
        """
        self.session_list.add(session)

    def set_is_expanded(self, is_expanded):
        """Set is_expanded.

        Args:
            is_expanded (bool): is_expanded.
        """
        self.is_expanded = is_expanded

    def save(self):
        """Write to __FolderData__.ini file."""
        with open(self.ini_path, "w") as ini_file:
            ini_file.write(
                'S:"Folder List"=' + ":".join(sorted(self.folder_list)) + ":\r\n"
            )
            ini_file.write(
                'S:"Session List"=' + ":".join(sorted(self.session_list)) + ":\r\n"
            )
            ini_file.write(
                'S:"Is Expanded"=' + "00000001"
                if self.is_expanded
                else "00000000" + "\r\n"
            )


class SecureCRTCryptoV2:
    """
    SecureCRT password encryption V2 implementation.

    Credit: https://github.com/HyperSine/how-does-SecureCRT-encrypt-password/blob/
            b9b39d26e54fba4c70fe23909e0e8e19b3ddddbb/python3/SecureCRTCipher.py
    """

    def __init__(self, ConfigPassphrase: str = ""):
        """
        Initialize SecureCRTCryptoV2 object.

        Args:
            ConfigPassphrase: The config passphrase that SecureCRT uses. Leave it empty if config passphrase is not set.
        """
        self.IV = b"\x00" * AES.block_size
        self.Key = SHA256.new(ConfigPassphrase.encode("utf-8")).digest()

    def encrypt(self, Plaintext: str):
        """
        Encrypt plaintext and return corresponding ciphertext.

        Args:
            Plaintext: A string that will be encrypted.

        Returns:
            Hexlified ciphertext string.
        """
        plain_bytes = Plaintext.encode("utf-8")
        if len(plain_bytes) > 0xFFFFFFFF:
            raise OverflowError("Plaintext is too long.")

        plain_bytes = (
            len(plain_bytes).to_bytes(4, "little")
            + plain_bytes
            + SHA256.new(plain_bytes).digest()
        )
        padded_plain_bytes = plain_bytes + os.urandom(
            AES.block_size - len(plain_bytes) % AES.block_size
        )
        cipher = AES.new(self.Key, AES.MODE_CBC, iv=self.IV)
        return cipher.encrypt(padded_plain_bytes).hex()

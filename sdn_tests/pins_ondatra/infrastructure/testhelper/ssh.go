package testhelper

import (
	"fmt"
	"time"
	"net"

	"os"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	sshPort        = 22
	sshUser        = "root"
	defaultTimeout = 30 * time.Second
)

// Function pointers that interact with the switch or the host.
// They enable unit testing of methods that interact with the switch or the host.
var (
	switchstackPrivateSSHRsaKey = func() (string, error) {

		b, err := os.ReadFile("/home/user/.ssh/key")
		return string(b), err
	}

	testhelperSSHDial = func(addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
		sshClient, err := ssh.Dial("tcp", fmt.Sprintf("[%s]:%d", addr, sshPort), config)
		if err != nil {
			return nil, WrapError(err, "failure to dial ssh")
		}
		return sshClient, nil
	}

	testhelperNewSSHSession = func(sshClient *ssh.Client) (*ssh.Session, error) {
		sshSession, err := sshClient.NewSession()
		if err != nil {
			return nil, WrapError(err, "failure to create ssh session")
		}
		return sshSession, nil
	}

	testhelperNewSFTPClient = func(sshClient *ssh.Client) (*sftp.Client, error) {
		sftpClient, err := sftp.NewClient(sshClient)
		if err != nil {
			return nil, WrapError(err, "failure to create sftp client")
		}
		return sftpClient, nil
	}

	testhelperCloseSSHClient = func(sshClient *ssh.Client) error {
		return sshClient.Close()
	}

	testhelperCloseSSHSession = func(sshSession *ssh.Session) error {
		return sshSession.Close()
	}

	testhelperCloseSFTPClient = func(sftpClient *sftp.Client) error {
		return sftpClient.Close()
	}

	testhelperOutputSSHSession = func(sshSession *ssh.Session, cmd string) ([]byte, error) {
		return sshSession.Output(cmd)
	}
)

// SSHManager provides two ssh objects: ssh.Session and sftp.Client.
type SSHManager struct {
	sshClient  *ssh.Client
	SSHSession *ssh.Session
	SFTPClient *sftp.Client
}

// NewSSHManager returns a new SSHManager, which contains two ssh objects that can help in ssh & scp.
func NewSSHManager(addr string) (*SSHManager, error) {
	manager := &SSHManager{}
	privKey, err := switchstackPrivateSSHRsaKey()
	if err != nil {
		return nil, WrapError(err, "failure to fetch ssh key")
	}
	signer, err := ssh.ParsePrivateKey([]byte(privKey))
	if err != nil {
		return nil, WrapError(err, "failure to parse ssh key")
	}
	authMethod := ssh.PublicKeys(signer)
	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: customInsecureIgnoreHostKey,
		Timeout:         defaultTimeout,
	}
	if manager.sshClient, err = testhelperSSHDial(addr, config); err != nil {
		return nil, err
	}
	if manager.SSHSession, err = testhelperNewSSHSession(manager.sshClient); err != nil {
		return nil, err
	}
	if manager.SFTPClient, err = testhelperNewSFTPClient(manager.sshClient); err != nil {
		return nil, err
	}

	return manager, nil
}
// Adding a coustom InsecureIgnoreHostKey to effectivly ignore host key verification
func customInsecureIgnoreHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	return nil
}
// Close must be called to close the SSHManager.
func (s *SSHManager) Close() error {
	var err error
	if e := testhelperCloseSSHSession(s.SSHSession); e != nil {
		err = WrapError(e, "failure in closing ssh.Session")
	}
	if e := testhelperCloseSFTPClient(s.SFTPClient); e != nil {
		err = WrapError(e, "failure in closing sftp.Client")
	}
	if e := testhelperCloseSSHClient(s.sshClient); e != nil {
		err = WrapError(e, "failure in closing ssh.Client")
	}
	return err
}

// RunSSH runs a single SSH command on the device and returns its standard output.
// Handles the creation and closing of SSHManager, since the underlying SSHSession can only call one
// command.
func RunSSH(addr string, cmd string) (string, error) {
	m, err := NewSSHManager(addr)
	if err != nil {
		return "", fmt.Errorf("failed to create ssh helper: %w", err)
	}
	defer m.Close()
	o, err := testhelperOutputSSHSession(m.SSHSession, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to run command '%s', output='%s', error: %w", cmd, string(o), err)
	}
	return string(o[:]), nil
}

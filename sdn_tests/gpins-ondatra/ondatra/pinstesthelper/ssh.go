package pinstesthelper

import (
	"fmt"
	"time"

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

	pinstesthelperSSHDial = func(addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
		sshClient, err := ssh.Dial("tcp", fmt.Sprintf("[%s]:%d", addr, sshPort), config)
		if err != nil {
			return nil, WrapError(err, "failure to dial ssh")
		}
		return sshClient, nil
	}

	pinstesthelperNewSSHSession = func(sshClient *ssh.Client) (*ssh.Session, error) {
		sshSession, err := sshClient.NewSession()
		if err != nil {
			return nil, WrapError(err, "failure to create ssh session")
		}
		return sshSession, nil
	}

	pinstesthelperNewSFTPClient = func(sshClient *ssh.Client) (*sftp.Client, error) {
		sftpClient, err := sftp.NewClient(sshClient)
		if err != nil {
			return nil, WrapError(err, "failure to create sftp client")
		}
		return sftpClient, nil
	}

	pinstesthelperCloseSSHClient = func(sshClient *ssh.Client) error {
		return sshClient.Close()
	}

	pinstesthelperCloseSSHSession = func(sshSession *ssh.Session) error {
		return sshSession.Close()
	}

	pinstesthelperCloseSFTPClient = func(sftpClient *sftp.Client) error {
		return sftpClient.Close()
	}

	pinstesthelperOutputSSHSession = func(sshSession *ssh.Session, cmd string) ([]byte, error) {
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         defaultTimeout,
	}
	if manager.sshClient, err = pinstesthelperSSHDial(addr, config); err != nil {
		return nil, err
	}
	if manager.SSHSession, err = pinstesthelperNewSSHSession(manager.sshClient); err != nil {
		return nil, err
	}
	if manager.SFTPClient, err = pinstesthelperNewSFTPClient(manager.sshClient); err != nil {
		return nil, err
	}

	return manager, nil
}

// Close must be called to close the SSHManager.
func (s *SSHManager) Close() error {
	var err error
	if e := pinstesthelperCloseSSHSession(s.SSHSession); e != nil {
		err = WrapError(e, "failure in closing ssh.Session")
	}
	if e := pinstesthelperCloseSFTPClient(s.SFTPClient); e != nil {
		err = WrapError(e, "failure in closing sftp.Client")
	}
	if e := pinstesthelperCloseSSHClient(s.sshClient); e != nil {
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
	o, err := pinstesthelperOutputSSHSession(m.SSHSession, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to run command '%s', output='%s', error: %w", cmd, string(o), err)
	}
	return string(o[:]), nil
}

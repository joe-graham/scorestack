package ssh_ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/scorestack/scorestack/dynamicbeat/checks/schema"
	"golang.org/x/crypto/ssh"
)

// The Definition configures the behavior of the SSH check
// it implements the "check" interface
type Definition struct {
	Config                          schema.CheckConfig // generic metadata about the check
	Username                        string             `optiontype:"required"` // The user to request a certificate for
	CaIP                            string             `optiontype:"required"` // The IP Address of the SSH Certificate Authority
	SSHCertificateAuthorityPassword string             `optiontype:"required"` // The admin password used to authenticate to the SSH Certificate Authority HTTP API
}

// Run a single instance of the check
func (d *Definition) Run(ctx context.Context) (result schema.CheckResult) {
	// 1. Generate Keypair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		result.Message = fmt.Sprintf("[CONTACT BLACK TEAM] failed to generate ECDSA private key: %v", err)
		return
	}

	// 2. Marshal Public Key
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		result.Message = fmt.Sprintf("[CONTACT BLACK TEAM] failed to marshal SSH public key: %v", err)
		return
	}
	b64pubkey := base64.StdEncoding.EncodeToString(ssh.MarshalAuthorizedKey(pub))

	// 3. Prepare HTTP Request
	params := &url.Values{}
	params.Set("user", d.Username)
	params.Set("b64pubkey", b64pubkey)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(
		"http://%s:8080/request_cert?%s",
		d.CaIP,
		params.Encode(),
	), nil)
	if err != nil {
		result.Message = fmt.Sprintf("[CONTACT BLACK TEAM] Failed to initialize HTTP request struct: %v", err)
		return
	}
	req.SetBasicAuth("admin", d.SSHCertificateAuthorityPassword)

	// 4. Request Certificate from SSH Certificate Authority
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(req)
	if err != nil {
		result.Message = fmt.Sprintf("failed to request SSH certificate from SSH Certificate Authority: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		result.Message = fmt.Sprintf("SSH Certificate Authority returned non 200 status code: %d", resp.StatusCode)
		return
	}

	// 5. Parse SSH Certificate from CA Response
	rawCert, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Message = fmt.Sprintf("failed to get SSH certificate from HTTP response body: %v", err)
		return
	}
	cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rawCert))
	if err != nil {
		result.Message = fmt.Sprintf("failed to parse SSH client certificate: %v", err)
	}
	sshCert, ok := cert.(*ssh.Certificate)
	if !ok {
		result.Message = fmt.Sprintf("received public key is not a valid ssh certificate")
		return
	}

	// 6. Request CA Public Key
	resp, err = http.Get(fmt.Sprintf("http://%s:8080/ca.pub", d.CaIP))
	if err != nil {
		result.Message = fmt.Sprintf("failed to retrieve public key from SSH Certificate Authority: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		result.Message = fmt.Sprintf("SSH Certificate Authority returned non-200 HTTP status code when requesting CA Public Key: %d", resp.StatusCode)
		return
	}

	// 7. Parse CA Public Key from CA Response
	caPub, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Message = fmt.Sprintf("failed to parse SSH Certificate Authority Public Key from HTTP response body: %v", err)
		return
	}

	certSignerPubkey := string(ssh.MarshalAuthorizedKey(sshCert.SignatureKey))

	if string(caPub) != certSignerPubkey {
		result.Message = fmt.Sprintf("signature mismatch: SSH Certificate was signed by a Public Key that does not belong to the SSH Certificate Authority")
		return
	}

	result.Passed = true
	return
}

// GetConfig returns the current CheckConfig struct this check has been
// configured with.
func (d *Definition) GetConfig() schema.CheckConfig {
	return d.Config
}

// SetConfig reconfigures this check with a new CheckConfig struct.
func (d *Definition) SetConfig(config schema.CheckConfig) {
	d.Config = config
}

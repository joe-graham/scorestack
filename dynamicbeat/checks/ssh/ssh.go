package ssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/elastic/beats/v7/libbeat/logp"

	"github.com/scorestack/scorestack/dynamicbeat/checks/schema"
	"golang.org/x/crypto/ssh"
)

// The Definition configures the behavior of the SSH check
// it implements the "check" interface
type Definition struct {
	Config                          schema.CheckConfig // generic metadata about the check
	Host                            string             `optiontype:"required"`                    // IP or hostname of the host to run the SSH check against
	Requests                        []*Request         `optiontype:"list"`                        // The user to login with over ssh
	CaIP                            string             `optiontype:"required"`                    // The IP Address of the SSH Certificate Authority
	SSHCertificateAuthorityPassword string             `optiontype:"required"`                    // The admin password used to authenticate to the SSH Certificate Authority HTTP API
	Cmd                             string             `optiontype:"required"`                    // The command to execute once ssh connection established
	MatchContent                    string             `optiontype:"optional"`                    // Whether or not to match content like checking files
	ContentRegex                    string             `optiontype:"optional" optiondefault:".*"` // Regex to match if reading a file
	Port                            string             `optiontype:"optional" optiondefault:"22"` // The port to attempt an ssh connection on
}

type Request struct {
	Username string `optiontype:"required"`
}

// Run a single instance of the check
func (d *Definition) Run(ctx context.Context) schema.CheckResult {
	// Initialize empty result
	result := schema.CheckResult{}

	request := d.Requests[0]
	if len(d.Requests) > 1 {
		if index, err := rand.Int(rand.Reader, big.NewInt(int64(len(d.Requests)))); err == nil {
			request = d.Requests[index.Int64()]
		}
	}
	user := request.Username

	// 1. Generate Keypair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		result.Message = fmt.Sprintf("[CONTACT BLACK TEAM] failed to generate ECDSA private key: %v", err)
		return result
	}

	// 2. Marshal Public Key
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		result.Message = fmt.Sprintf("[CONTACT BLACK TEAM] failed to marshal SSH public key: %v", err)
		return result
	}
	b64pubkey := base64.StdEncoding.EncodeToString(ssh.MarshalAuthorizedKey(pub))

	// 3. Create Signer using Private Key
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		result.Message = fmt.Sprintf("[CONTACT BLACK TEAM] failed to create signer from ssh private key: %v", err)
		return result
	}

	// 4. Prepare HTTP Request
	params := &url.Values{}
	params.Set("user", user)
	params.Set("b64pubkey", b64pubkey)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(
		"http://%s:8080/request_cert?%s",
		d.CaIP,
		params.Encode(),
	), nil)
	if err != nil {
		result.Message = fmt.Sprintf("[CONTACT BLACK TEAM] Failed to initialize HTTP request struct: %v", err)
		return result
	}
	req.SetBasicAuth("admin", d.SSHCertificateAuthorityPassword)

	// 5. Request Certificate from SSH Certificate Authority
	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		result.Message = fmt.Sprintf("failed to request SSH certificate from SSH Certificate Authority: %v", err)
		return result
	}
	if resp.StatusCode == http.StatusUnauthorized {
		result.Message = fmt.Sprintf("Failed to authenticate to SSH Certificate Authority while requesting SSH User Certificate (if you've changed the password, be sure to update the scoring checks with the new credentials). SSH Certificate Authority returned non 200 status code: %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		result.Message = fmt.Sprintf("SSH Certificate Authority returned non 200 status code: %d", resp.StatusCode)
		return result
	}

	// 6. Parse SSH Certificate from CA Response
	rawCert, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Message = fmt.Sprintf("failed to get SSH certificate from HTTP response body: %v", err)
		return result
	}
	cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rawCert))
	if err != nil {
		result.Message = fmt.Sprintf("failed to parse SSH client certificate: %v", err)
		return result
	}
	sshCert, ok := cert.(*ssh.Certificate)
	if !ok {
		result.Message = fmt.Sprintf("received public key is not a valid ssh certificate")
		return result
	}

	// 7. Combine SSH Certificate & PrivateKey into Signer auth method
	sshCertSigner, err := ssh.NewCertSigner(sshCert, signer)
	if err != nil {
		result.Message = fmt.Sprintf("failed to use certificate as an auth method, perhaps the private key is a mismatch: %v", err)
		return result
	}

	// 8. Configure SSH Client
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(sshCertSigner),
		},
		Timeout:         20 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 9. Create the ssh client
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", d.Host, d.Port), config)
	if err != nil {
		result.Message = fmt.Sprintf("SSH failed to connect. Successfully retrieved SSH User Certificate, but either the SSH server did not accept it or it failed for another reason: (user: %s) %s", user, err)
		return result
	}
	defer func() {
		err = client.Close()
		if err != nil {
			logp.Warn("Failed to close SSH connection: %s", err)
		}
	}()

	// 10. Create a session from the connection
	session, err := client.NewSession()
	if err != nil {
		result.Message = fmt.Sprintf("Error creating a ssh session: %s", err)
		return result
	}
	defer func() {
		err = session.Close()
		if err != nil {
			logp.Warn("Failed to close SSH session connection: %s", err)
		}
	}()

	// 11. Run a command
	output, err := session.CombinedOutput(d.Cmd)
	if err != nil {
		result.Message = fmt.Sprintf("Error executing command: %s", err)
		return result
	}

	// 12. Check if we are going to match content
	if matchContent, _ := strconv.ParseBool(d.MatchContent); !matchContent {
		// If we made it here the check passes
		result.Message = fmt.Sprintf("Command %s executed successfully: %s", d.Cmd, output)
		result.Passed = true
		return result
	}

	// 13. Match some content
	regex, err := regexp.Compile(d.ContentRegex)
	if err != nil {
		result.Message = fmt.Sprintf("Error compiling regex string %s : %s", d.ContentRegex, err)
		return result
	}

	// 14. Check if the content matches
	if !regex.Match(output) {
		result.Message = fmt.Sprintf("Matching content not found")
		return result
	}

	// 15. If we reach here the check is successful
	result.Passed = true
	return result
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

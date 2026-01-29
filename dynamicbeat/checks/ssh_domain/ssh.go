package ssh_domain

import (
	"context"
	"fmt"
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
	Config   schema.CheckConfig // generic metadata about the check
	Host     string             `optiontype:"required"` // IP or hostname of the host to run the SSH check against
	Username string             `optiontype:"required"` // IP or hostname of the host to run the SSH check against
	Password string             `optiontype:"required"` // IP or hostname of the host to run the SSH check against

	Cmd          string `optiontype:"required"`                    // The command to execute once ssh connection established
	MatchContent string `optiontype:"optional"`                    // Whether or not to match content like checking files
	ContentRegex string `optiontype:"optional" optiondefault:".*"` // Regex to match if reading a file
	Port         string `optiontype:"optional" optiondefault:"22"` // The port to attempt an ssh connection on
}

type Request struct {
	Username string `optiontype:"required"`
}

// Run a single instance of the check
func (d *Definition) Run(ctx context.Context) schema.CheckResult {
	// Initialize empty result
	result := schema.CheckResult{}

	// 1. Configure SSH Client
	config := &ssh.ClientConfig{
		User: `nc\` + d.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(d.Password),
		},
		Timeout:         20 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 2. Create the ssh client
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", d.Host, d.Port), config)
	if err != nil {
		result.Message = fmt.Sprintf("SSH failed to connect (user: %s): %s", d.Username, err)
		return result
	}
	defer func() {
		err = client.Close()
		if err != nil {
			logp.Warn("Failed to close SSH connection: %s", err)
		}
	}()

	// 3. Create a session from the connection
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

	// 4. Run a command
	output, err := session.CombinedOutput(d.Cmd)
	if err != nil {
		result.Message = fmt.Sprintf("Error executing command: %s", err)
		return result
	}

	// 5. Check if we are going to match content
	if matchContent, _ := strconv.ParseBool(d.MatchContent); !matchContent {
		// If we made it here the check passes
		result.Message = fmt.Sprintf("Command %s executed successfully: %s", d.Cmd, output)
		result.Passed = true
		return result
	}

	// 6. Match some content
	regex, err := regexp.Compile(d.ContentRegex)
	if err != nil {
		result.Message = fmt.Sprintf("Error compiling regex string %s : %s", d.ContentRegex, err)
		return result
	}

	// 7. Check if the content matches
	if !regex.Match(output) {
		result.Message = fmt.Sprintf("Matching content not found")
		return result
	}

	// 8. If we reach here the check is successful
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

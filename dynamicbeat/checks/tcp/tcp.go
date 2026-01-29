package tcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/scorestack/scorestack/dynamicbeat/checks/schema"
)

// The Definition configures the behavior of a Noop check.
type Definition struct {
	Config               schema.CheckConfig // generic metadata about the check
	Host                 string             `optiontype:"required"` // IP or hostname to run the TCP check against
	Port                 string             `optiontype:"required"` // The port to attempt to connect to
	Input                string             `optiontype:"optional"` // A base64 string of input to write into the socket.
	MatchContent         string             `optiontype:"required"` // Whether to match content returned by the TCP connection
	ReportMatchedContent string             `optiontype:"optional"` // Whether to return matched content with check result
	ContentRegex         string             `optiontype:"optional"` // The regex for response to match on. Cannot be used with ContentBase64.
	ContentBase64        string             `optiontype:"optional"` // The base64 of an expected output, in case it's bytes. Cannot be used with ContentRegex.
}

// Run a single instance of the check.
func (d *Definition) Run(ctx context.Context) schema.CheckResult {
	// Initialize empty result
	result := schema.CheckResult{}

	// parse strs into bools
	matchContent, _ := strconv.ParseBool(d.MatchContent)
	reportMatchedContent, _ := strconv.ParseBool(d.ReportMatchedContent)

	// build connection string
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s:%s", d.Host, d.Port)

	// context to allow timeout
	ctxDial, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctxDial, "tcp", builder.String())

	if err != nil {
		result.Message = fmt.Sprintf("Error connecting to host: %s", err)
		return result
	}
	defer conn.Close()

	// pass input to socket
	if strings.Compare(d.Input, "<no value>") != 0 {
		var data []byte
		logp.Info("Length of input: %d", len(d.Input))
		logp.Info("Content of base64: %v", d.Input)
		data, err = base64.StdEncoding.DecodeString(d.Input)
		if err != nil {
			logp.Info("Error decoding input from base64: %s", err)
			return result
		}
		_, err = conn.Write(data)

		if err != nil {
			logp.Info("Error writing input to socket: %s", err)
			return result
		}
	}

	if matchContent {
		var returnedContent bytes.Buffer

		_, err = io.Copy(&returnedContent, conn)
		if err != nil {
			logp.Info("Error reading bytes from socket: %s", err)
			return result
		}

		var pass bool
		var match *string

		if len(d.ContentRegex) > 0 && len(d.ContentBase64) > 0 {
			logp.Info("Error, cannot have both regex and base64 string to evaluate returned content on.")
			return result
		} else {
			if len(d.ContentRegex) > 0 {
				pass, match, err = parseContentRegex(returnedContent, d.ContentRegex)
				details := make(map[string]string)
				if match != nil && reportMatchedContent {
					details["matched_content"] = *match
				}
			} else {
				pass, err = parseContentBase64(returnedContent, d.ContentBase64)
			}
			result.Passed = pass
			if err != nil {
				result.Message = fmt.Sprintf("%s", err)
			}
		}

	} else {
		// if got this far, socket is open and therefore passing
		result.Passed = true
	}

	return result
}

func parseContentRegex(buf bytes.Buffer, regexStr string) (bool, *string, error) {
	content := buf.Bytes()
	regex, err := regexp.Compile(regexStr)
	if err != nil {
		return false, nil, fmt.Errorf("error compiling regex string %s : %s", regex, err)
	}

	if !regex.Match(content) {
		return false, nil, fmt.Errorf("content doesn't match regex")
	}
	matches := regex.FindSubmatch(content)
	matchStr := fmt.Sprintf("%s", matches[len(matches)-1])
	return true, &matchStr, nil
}

func parseContentBase64(buf bytes.Buffer, b64str string) (bool, error) {
	content := buf.Bytes()
	var contentb64 strings.Builder
	encoder := base64.NewEncoder(base64.StdEncoding, &contentb64)
	encoder.Write(content)
	if strings.Compare(contentb64.String(), b64str) != 0 {
		return false, fmt.Errorf("base64 string of content returned by socket %s did not match configured base64 %s", contentb64.String(), b64str)
	} else {
		return true, nil
	}
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

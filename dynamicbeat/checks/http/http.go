package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/scorestack/scorestack/dynamicbeat/checks/schema"
	"golang.org/x/net/proxy"
)

// The Definition configures the behavior of an HTTP check.
type Definition struct {
	Config               schema.CheckConfig // generic metadata about the check
	Verify               string             `optiontype:"optional"` // whether HTTPS certs should be validated
	ReportMatchedContent string             `optiontype:"optional"` // whether the matched content should be returned in the CheckResult
	ProxyURL             string             `optiontype:"optional"` // URL used to route requests through an HTTP, HTTPS, or SOCKS5 proxy
	Requests             []*Request         `optiontype:"list"`     // a list of requests to make
}

// A Request represents a single HTTP request to make.
type Request struct {
	Host         string            `optiontype:"required"`                     // IP or FQDN of the HTTP server
	Path         string            `optiontype:"required"`                     // Path to request - see RFC3986, section 3.3
	HTTPS        bool              `optiontype:"optional"`                     // if HTTPS is to be used
	Port         uint16            `optiontype:"optional" optiondefault:"80"`  // TCP port number the HTTP server is listening on
	Method       string            `optiontype:"optional" optiondefault:"GET"` // HTTP method to use
	Headers      map[string]string `optiontype:"optional"`                     // name-value pairs of header fields to add/override
	Body         string            `optiontype:"optional"`                     // the request body
	MatchCode    bool              `optiontype:"optional"`                     // whether the response code must match a defined value for the check to pass
	Code         int               `optiontype:"optional" optiondefault:"200"` // the response status code to match
	MatchContent bool              `optiontype:"optional"`                     // whether the response body must match a defined regex for the check to pass
	ContentRegex string            `optiontype:"optional" optiondefault:".*"`  // regex for the response body to match
	StoreValue   bool              `optiontype:"optional"`                     // whether the matched content should be saved for use in a later request
}

// Run a single instance of the check.
func (d *Definition) Run(ctx context.Context) schema.CheckResult {
	// Initialize empty result
	result := schema.CheckResult{}

	// Convert strings to booleans to allow templating
	verify, _ := strconv.ParseBool(d.Verify)
	reportMatchedContent, _ := strconv.ParseBool(d.ReportMatchedContent)

	// Define transport in case new properties are added to it

	transport := &http.Transport{
		IdleConnTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !verify,
		},
	}

	if len(d.ProxyURL) > 0 {
		// Parse proxy URL
		proxyURL, err := url.Parse(d.ProxyURL)
		if err != nil {
			logp.Info("Error parsing proxy URL: %s", err)
			return result
		}

		dial, err := proxy.FromURL(proxyURL, proxy.Direct)
		if err != nil {
			logp.Info("Error creating dialer: %s", err)
			return result
		}
		transport.Dial = dial.Dial
	}

	// Configure HTTP client
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		result.Message = "Could not create CookieJar"
		return result
	}
	// TODO: change http.Client.Timeout to be relative to the parent context's
	// timeout
	client := &http.Client{
		Jar:       cookieJar,
		Transport: transport,
	}

	// Save match strings
	var lastMatch *string
	var storedValue *string

	type storedValTempl struct {
		SavedValue string
	}

	// Make each request in the list
	// TODO: use "happy line" structure instead of deeply-nested if statements
	for _, r := range d.Requests {
		// Check to see if the StoredValue needs to be templated in
		if storedValue != nil {
			// Re-encode definition to JSON string
			def, err := json.Marshal(r)
			if err != nil {
				logp.Info("Error encoding HTTP definition as JSON for StoredValue templating: %s", err)
			} else {
				attrs := storedValTempl{
					SavedValue: *storedValue,
				}
				templ := template.Must(template.New("http-storedvalue").Parse(string(def)))
				var buf bytes.Buffer
				err := templ.Execute(&buf, attrs)
				if err != nil {
					logp.Info("Error templating HTTP definition for StoredValue templating: %s", err)
				} else {
					newReq := &Request{}
					err := json.Unmarshal(buf.Bytes(), &newReq)
					if err != nil {
						logp.Info("Error decoding StoredValue-templated HTTP definition: %s", err)
					} else {
						r = newReq
					}
				}
			}
		}

		// TODO: create child context with deadline less than the parent context
		pass, match, err := request(ctx, client, *r)

		// Process request results
		result.Passed = pass
		if err != nil {
			result.Message = fmt.Sprintf("%s", err)
		}
		if match != nil {
			lastMatch = match
			if r.StoreValue {
				storedValue = match
			}
		}

		// If this request failed, don't continue on to the next request
		if !pass {
			break
		}
	}

	details := make(map[string]string)
	if reportMatchedContent && lastMatch != nil {
		details["matched_content"] = *lastMatch
	}
	result.Details = details

	return result
}

func request(ctx context.Context, client *http.Client, r Request) (bool, *string, error) {
	// Construct URL
	var schema string
	if r.HTTPS {
		schema = "https"
	} else {
		schema = "http"
	}
	url := fmt.Sprintf("%s://%s:%d%s", schema, r.Host, r.Port, r.Path)

	// Construct request
	req, err := http.NewRequestWithContext(ctx, r.Method, url, strings.NewReader(r.Body))
	if err != nil {
		return false, nil, fmt.Errorf("Error constructing request: %s", err)
	}

	// Add headers
	for k, v := range r.Headers {
		req.Header[k] = []string{v}
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("Error making request: %s", err)
	}
	defer resp.Body.Close()

	// Check status code
	if r.MatchCode && resp.StatusCode != r.Code {
		return false, nil, fmt.Errorf("Recieved bad status code: %d", resp.StatusCode)
	}

	// Check body content
	var matchStr string
	if r.MatchContent {
		// Read response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, nil, fmt.Errorf("Recieved error when reading response body: %s", err)
		}

		// Check if body matches regex
		regex, err := regexp.Compile(r.ContentRegex)
		if err != nil {
			return false, nil, fmt.Errorf("Error compiling regex string %s : %s", r.ContentRegex, err)
		}
		if !regex.Match(body) {
			return false, nil, fmt.Errorf("recieved bad response body")
		}
		matches := regex.FindSubmatch(body)
		matchStr = fmt.Sprintf("%s", matches[len(matches)-1])
	}

	// If we've reached this point, then the check succeeded
	return true, &matchStr, nil
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

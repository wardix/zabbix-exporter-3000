package zabbix

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	cnf "github.com/rzrbld/zabbix-exporter-3000/config"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

// Request represents a JSON-RPC request to be sent to the Zabbix API.
type Request struct {
	JSONRPCVersion string      `json:"jsonrpc"`
	Method         string      `json:"method"`
	Params         interface{} `json:"params"`
	RequestID      uint64      `json:"id"`
	AuthToken      string      `json:"auth,omitempty"`
}

// APIError represents the error structure returned by the Zabbix API.
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

// Response represents the response from a Zabbix API JSON-RPC request.
type Response struct {
	StatusCode     int             `json:"-"`
	JSONRPCVersion string          `json:"jsonrpc"`
	Body           json.RawMessage `json:"result"`
	RequestID      uint64          `json:"id"`
	Error          APIError        `json:"error"`
}

// Err returns an error if the Response includes any error information returned
// from the Zabbix API.
func (c *Response) Err() error {
	if c.Error.Code != 0 {
		return fmt.Errorf("HTTP %d %s (%d)\n%s", c.StatusCode, c.Error.Message, c.Error.Code, c.Error.Data)
	}
	return nil
}

// Bind unmarshals the JSON body of the Response into the given interface.
func (c *Response) Bind(v interface{}) error {
	err := json.Unmarshal(c.Body, v)
	if err != nil {
		return fmt.Errorf("Error decoding JSON response body: %v", err)
	}
	return nil
}

// ZabbixSession represents an authenticated Zabbix JSON-RPC API client.
type ZabbixSession struct {
	URL        string `json:"url"`
	Token      string `json:"token"`
	HTTPClient *http.Client
}

var Session, err = Connect()
var Query *Request

// AuthToken returns the authentication token used by this session.
func (c *ZabbixSession) AuthToken() string {
	return c.Token
}

// GetVersion returns the software version string of the connected Zabbix API.
func (c *ZabbixSession) GetVersion() (string, error) {
	return "7.2+", nil
}

// Do sends a JSON-RPC request and returns an API Response.
func (c *ZabbixSession) Do(req *Request) (resp *Response, err error) {
	// Always omit auth parameter from body for Zabbix >= 7.2
	req.AuthToken = ""

	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	r, err := http.NewRequest("POST", c.URL, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	r.ContentLength = int64(len(b))
	r.Header.Add("Content-Type", "application/json-rpc")

	// Always set Bearer token header for Zabbix >= 7.2
	if c.Token != "" {
		r.Header.Set("Authorization", "Bearer "+c.Token)
	}

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	respBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response: %v", err)
	}

	resp = &Response{
		StatusCode: res.StatusCode,
	}

	err = json.Unmarshal(respBytes, &resp)
	if err != nil {
		return nil, fmt.Errorf("Error decoding JSON response body: %v", err)
	}

	if err = resp.Err(); err != nil {
		return resp, err
	}

	return resp, nil
}

// Connect establishes connection to Zabbix, verifies session cache or logs in.
func Connect() (*ZabbixSession, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cnf.SslSkip}}}

	sess := &ZabbixSession{
		URL:        cnf.Server,
		HTTPClient: client,
	}

	// 1. Read cache if exists
	cachePath := "./zabbix_session"
	var cachedToken string
	if data, err := os.ReadFile(cachePath); err == nil {
		cachedToken = strings.TrimSpace(string(data))
	}

	if cachedToken != "" {
		sess.Token = cachedToken
		// Verify cached token using user.get (requires auth)
		if verifyToken(sess) {
			log.Print("Reusing cached Zabbix session token.")
		} else {
			log.Print("Cached Zabbix session token is invalid or expired. Performing fresh login...")
			sess.Token = ""
		}
	}

	// 2. Login if no valid token
	if sess.Token == "" {
		token, err := login(sess, cnf.User, cnf.Password)
		if err != nil {
			log.Fatalf("Failed Zabbix login: %v\n", err)
		}
		sess.Token = token
		// Save token to cache
		_ = os.WriteFile(cachePath, []byte(token), 0644)
	}

	// Mask and log the token
	authToken := sess.Token
	sToken := strings.Split(authToken, "")
	if len(sToken) >= 7 {
		log.Print("Auth: ", sToken[0], sToken[1], sToken[2], sToken[3], sToken[4], sToken[5], sToken[6])
	} else {
		log.Print("Auth: ", authToken)
	}

	// 3. Set up the dynamic query replacing placeholders
	var err error
	strRequestWithAuth := strings.Replace(cnf.Query, "%auth-token%", authToken, -1)
	err = json.Unmarshal([]byte(strRequestWithAuth), &Query)
	if err != nil {
		log.Print("ERROR While convert request to JSON: ", err)
	}

	// Unconditionally convert application query to tags since Zabbix >= 7.2 does not support applications
	if Query != nil {
		if paramsMap, ok := Query.Params.(map[string]interface{}); ok {
			if appName, exists := paramsMap["application"]; exists {
				log.Printf("Converting deprecated 'application': '%s' parameter to standard tags syntax for Zabbix >= 7.2.", appName)
				delete(paramsMap, "application")
				paramsMap["tags"] = []map[string]interface{}{
					{
						"tag":      "Application",
						"value":    appName,
						"operator": 0, // 0 = Contains, 1 = Equals
					},
				}
				Query.Params = paramsMap
			}
		}
	}

	if Query != nil {
		Query.AuthToken = "" // Ensure omitted in serialization
	}

	log.Print("Connected to Zabbix API v7.2+")
	return sess, nil
}

// Helper to verify if token is valid
func verifyToken(s *ZabbixSession) bool {
	req := &Request{
		JSONRPCVersion: "2.0",
		Method:         "user.get",
		Params: map[string]interface{}{
			"limit": 1,
		},
		RequestID: 1,
	}
	_, err := s.Do(req)
	return err == nil
}

// Helper to perform Zabbix login for Zabbix >= 7.2 (requires username)
func login(s *ZabbixSession, user, password string) (string, error) {
	req := &Request{
		JSONRPCVersion: "2.0",
		Method:         "user.login",
		Params: map[string]interface{}{
			"username": user,
			"password": password,
		},
		RequestID: 1,
	}
	resp, err := s.Do(req)
	if err != nil {
		return "", err
	}
	var token string
	if err := json.Unmarshal(resp.Body, &token); err != nil {
		return "", err
	}
	return token, nil
}

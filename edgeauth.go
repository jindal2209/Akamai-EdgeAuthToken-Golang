package edgeauth

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Algo           crypto.Hash
	Key            string
	Salt           string
	FieldDelimiter string
	ACLDelimiter   string
	StartTime      time.Time
	EndTime        time.Time
	DurationWindow time.Duration
	IP             string
	SessionID      string
	Payload        string
	Verbose        bool
	Token          string
	EscapeEarly    bool
}

type Client struct {
	Config *Config
}

func NewClient(config *Config) (*Client, error) {
	if config.Algo == 0 {
		config.Algo = crypto.SHA256
	}

	if config.FieldDelimiter == "" {
		config.FieldDelimiter = "~"
	}

	if config.ACLDelimiter == "" {
		config.ACLDelimiter = "!"
	}

	if config.Token == "" {
		config.Token = "__token__"
	}

	if config.Key == "" {
		return nil, errors.New("you must provide key")
	}

	return &Client{config}, nil
}

func createSignature(hasher func() hash.Hash, value string, key []byte) string {
	hm := hmac.New(hasher, key)
	hm.Write([]byte(value))

	return hex.EncodeToString(hm.Sum(nil))
}

func encodePath(path string) string {
	path = url.QueryEscape(path)
	path = strings.ToLower(path)
	return path
}

func (c *Client) escapeEarly(text string) string {
	if c.Config.EscapeEarly {
		return encodePath(text)
	}
	return text
}

func (c *Client) generateToken(path string, isUrl bool) (string, error) {
	var hasher func() hash.Hash

	switch c.Config.Algo {
	case crypto.SHA256:
		hasher = sha256.New
	case crypto.SHA1:
		hasher = sha1.New
	case crypto.MD5:
		hasher = md5.New
	default:
		return "", errors.New("altorithm should be sha256 or sha1 or md5")
	}

	now := time.Now()
	startTime := c.Config.StartTime
	endTime := c.Config.EndTime

	if startTime.IsZero() {
		startTime = now
	}

	if endTime.IsZero() {
		if c.Config.DurationWindow == 0 {
			return "", errors.New("you must provide end time or duration window")
		}

		endTime = startTime.Add(c.Config.DurationWindow)
	}

	if startTime.Equal(endTime) {
		return "", errors.New("start and end time cannot be the same")
	}

	if endTime.Before(startTime) {
		return "", errors.New("end time must be greater than start time")
	}

	if endTime.Before(now) {
		return "", errors.New("end time must be in the future")
	}

	if c.Config.Verbose {
		fmt.Println("Akamai Token Generation Parameters")
		if isUrl {
			fmt.Println("URL			:", path)
		} else {
			fmt.Println("ACL			:", path)
		}
		fmt.Println("Start Time		:", c.Config.StartTime.Format(time.RFC3339))
		fmt.Println("End Time		:", c.Config.EndTime.Format(time.RFC3339))
		fmt.Println("Duration		:", c.Config.DurationWindow)
		fmt.Println("Payload		:", c.Config.Payload)
		fmt.Println("Algo			:", c.Config.Algo)
		fmt.Println("Salt			:", c.Config.Salt)
		fmt.Println("FieldDelimiter	:", c.Config.FieldDelimiter)
		fmt.Println("ACLDelimiter	:", c.Config.ACLDelimiter)
		fmt.Println("EscapeEarly	:", c.Config.EscapeEarly)
		fmt.Println("SessionID		:", c.Config.SessionID)
	}

	query := []string{}

	if c.Config.IP != "" {
		query = append(query, "ip="+c.escapeEarly(c.Config.IP))
	}

	// Include StartTime only if explicitly given
	if !c.Config.StartTime.IsZero() {
		query = append(query, "st="+strconv.FormatInt(c.Config.StartTime.Unix(), 10))
	}

	query = append(query, "exp="+strconv.FormatInt(endTime.Unix(), 10))

	if !isUrl {
		query = append(query, "acl="+path)
	}

	if c.Config.SessionID != "" {
		query = append(query, "id="+c.escapeEarly(c.Config.SessionID))
	}

	if c.Config.Payload != "" {
		query = append(query, "data="+c.escapeEarly(c.Config.Payload))
	}

	hashSource := make([]string, len(query))
	copy(hashSource, query)

	if isUrl {
		hashSource = append(hashSource, "url="+c.escapeEarly(path))
	}

	if c.Config.Salt != "" {
		hashSource = append(hashSource, "salt="+c.Config.Salt)
	}

	key, err := hex.DecodeString(c.Config.Key)

	if err != nil {
		return "", err
	}

	token := createSignature(
		hasher,
		strings.Join(hashSource, c.Config.FieldDelimiter),
		key,
	)

	query = append(query, "hmac="+token)

	return strings.Join(query, c.Config.FieldDelimiter), nil
}

func (c *Client) GenerateACLToken(acl []string) (string, error) {
	var path string
	if len(acl) == 0 {
		return "", errors.New("you must provide acl(s)")
	} else if len(acl) == 1 {
		path = acl[0]
	} else {
		path = strings.Join(acl, c.Config.ACLDelimiter)
	}
	return c.generateToken(path, false)
}

func (c *Client) GenerateURLToken(url string) (string, error) {
	if url == "" {
		return "", errors.New("you must provide a url")
	}
	return c.generateToken(url, true)
}

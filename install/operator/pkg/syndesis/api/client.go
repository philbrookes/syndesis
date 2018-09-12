package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	glog "github.com/syndesisio/syndesis/install/operator/dep-cache/sources/https---github.com-golang-glog"
	v1alpha1 "github.com/syndesisio/syndesis/install/operator/pkg/apis/syndesis/v1alpha1"
)

type Client interface {
	CreateConnection(connection *v1alpha1.Connection) error
}

type ConnectionCreatePost struct {
	ConfiguredProperties ConfiguredProperties `json:"configuredProperties"`
	Name                 string               `json:"name"`
}

type ConfiguredProperties struct {
	ConnectionURI        string `json:"connectionUri"`
	Username             string `json:"username"`
	Password             string `json:"password"`
	SkipCertificateCheck bool   `json:"skipCertificateCheck"`
	BrokerCertificate    string `json:"brokerCertificate"`
}

type SyndesisClient struct {
	token     string
	host      string
	user      string
	xsrfToken string
	client    *http.Client
}

func NewClient(token, host, user, xsrfToken string, httpClient *http.Client) Client {
	return &SyndesisClient{
		token:     token,
		host:      host,
		user:      user,
		xsrfToken: xsrfToken,
		client:    httpClient,
	}
}

func (c *SyndesisClient) CreateConnection(connection *v1alpha1.Connection) error {
	glog.Infof("Creating connection")
	apiHost := "http://" + c.host + "/api/v1/connections"
	body, err := getBody(connection.Spec.Username, connection.Spec.Password, connection.Spec.URL, connection.ObjectMeta.Name)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", apiHost, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-FORWARDED-USER", c.user)
	req.Header.Set("X-FORWARDED-ACCESS-TOKEN", c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("SYNDESIS-XSRF-TOKEN", c.xsrfToken)
	rsp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != 200 {
		return fmt.Errorf("error creating connection")
	}
	return nil
}

func getBody(username, password, url, connectionName string) (*bytes.Buffer, error) {
	body := ConnectionCreatePost{
		ConfiguredProperties: ConfiguredProperties{
			BrokerCertificate:    "",
			SkipCertificateCheck: true,
			ConnectionURI:        url,
			Username:             username,
			Password:             password,
		},
		Name: connectionName,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(bodyBytes), nil
}

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	glog "github.com/golang/glog"
	v1alpha1 "github.com/syndesisio/syndesis/install/operator/pkg/apis/syndesis/v1alpha1"
)

type Client interface {
	CreateConnection(connection *v1alpha1.Connection) error
}

type ConnectionCreatePost struct {
	ConfiguredProperties ConfiguredProperties `json:"configuredProperties"`
	Name                 string               `json:"name"`
	Connector            Connector            `json:"connector"`
	Icon                 string               `json:"icon"`
	ConnectorID          string               `json:"connectorId"`
}

type Connector struct {
	Description      string                `json:"description"`
	Icon             string                `json:"icon"`
	ComponentScheme  string                `json:"componentScheme"`
	ConnectorFactory string                `json:"connectorFactory"`
	ID               string                `json:"id"`
	Version          string                `json:"version"`
	Dependencies     []ConnectorDependency `json:"dependencies"`
	Actions          []ConnectorAction     `json:"actions"`
}

type ConnectorAction struct {
	ID          string                    `json:""`
	Name        string                    `json:""`
	Description string                    `json:""`
	Descriptor  ConnectorActionDescriptor `json:"descriptor"`
	ActionType  string                    `json:"actionType"`
	Pattern     string                    `json:"pattern"`
}

type ConnectorActionDescriptorDataShape struct {
	Kind string `json:"kind"`
}

type ConnectorActionDescriptorPropertyEnum struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type ConnectorActionDescriptorPropertyDefinitionStep struct {
	Description string `json:"description"`
	Name        string `json:"name"`
	Properties  map[string]ConnectorActionDescriptorPropertyDefinitionStepProperties
}

type ConnectorActionDescriptorPropertyDefinitionStepProperties struct {
	ComponentProperty bool                                    `json:"componentProperty,omitempty"`
	Deprecated        bool                                    `json:"deprecated,omitempty"`
	LabelHint         string                                  `json:"labelHint,omitempty"`
	DisplayName       string                                  `json:"displayName,omitempty"`
	Group             string                                  `json:"group,omitempty"`
	JavaType          string                                  `json:"javaType,omitempty"`
	Kind              string                                  `json:"kind,omitempty"`
	Required          bool                                    `json:"required,omitempty"`
	Secret            bool                                    `json:"secret,omitempty"`
	Type              string                                  `json:"type,omitempty"`
	Order             int                                     `json:"order,omitempty"`
	DefaultValue      string                                  `json:"defaultValue,omitempty"`
	Label             string                                  `json:"label,omitempty"`
	Enum              []ConnectorActionDescriptorPropertyEnum `json:"enum,omitempty"`
}

type ConnectorActionDescriptor struct {
	InputDataShape          ConnectorActionDescriptorDataShape                `json:"inputDataShape"`
	OutputDataShape         ConnectorActionDescriptorDataShape                `json:"outputDataShape"`
	PropertyDefinitionSteps []ConnectorActionDescriptorPropertyDefinitionStep `json:"propertyDefinitionSteps"`
}

type ConnectorDependency struct {
	Type string `json:"type"`
	ID   string `json:"id"`
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
	body, err := newConnectionCreatePostBody(connection.Spec.Username, connection.Spec.Password, connection.Spec.URL, connection.ObjectMeta.Name)
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

func newConnectionCreatePostBody(username, password, url, connectionName string) (*bytes.Buffer, error) {
	body := ConnectionCreatePost{
		Name:        connectionName,
		Icon:        "fa-amqp",
		ConnectorID: "amqp",
		ConfiguredProperties: ConfiguredProperties{
			BrokerCertificate:    "",
			SkipCertificateCheck: true,
			ConnectionURI:        url,
			Username:             username,
			Password:             password,
		},
		Connector: Connector{
			Description:      "Subscribe for and publish messages.",
			Icon:             "fa-amqp",
			ComponentScheme:  "amqp",
			ConnectorFactory: "io.syndesis.connector.amqp.AMQPConnectorFactory",
			ID:               "amqp",
			Version:          "1",
			Dependencies: []ConnectorDependency{
				{
					Type: "MAVEN",
					ID:   "io.syndesis.connector:connector-amqp:1.5-SNAPSHOT",
				},
			},
			Actions: []ConnectorAction{
				{
					ID:          "io.syndesis:amqp-publish-action",
					Name:        "Publish messages",
					Description: "Send data to the destination you specify.",
					Descriptor: ConnectorActionDescriptor{
						InputDataShape: ConnectorActionDescriptorDataShape{
							Kind: "any",
						},
						OutputDataShape: ConnectorActionDescriptorDataShape{
							Kind: "none",
						},
						PropertyDefinitionSteps: []ConnectorActionDescriptorPropertyDefinitionStep{
							{
								Description: "Specify AMQP destination properties, including Queue or Topic name",
								Name:        "Select the AMQP Destination",
								Properties: map[string]ConnectorActionDescriptorPropertyDefinitionStepProperties{
									"DestinationName": ConnectorActionDescriptorPropertyDefinitionStepProperties{
										ComponentProperty: false,
										Deprecated:        false,
										LabelHint:         "Name of the queue or topic to send data to.",
										DisplayName:       "Destination Name",
										Group:             "common",
										JavaType:          "java.lang.String",
										Kind:              "path",
										Required:          true,
										Secret:            false,
										Type:              "string",
										Order:             1,
									},
									"DestinationType": ConnectorActionDescriptorPropertyDefinitionStepProperties{
										ComponentProperty: false,
										DefaultValue:      "queue",
										Deprecated:        false,
										LabelHint:         "By default, the destination is a Queue.",
										DisplayName:       "Destination Type",
										Group:             "common",
										JavaType:          "java.lang.String",
										Kind:              "path",
										Required:          false,
										Secret:            false,
										Type:              "string",
										Order:             2,
										Enum: []ConnectorActionDescriptorPropertyEnum{
											{
												Label: "Topic",
												Value: "topic",
											},
											{
												Label: "Queue",
												Value: "queue",
											},
										},
									},
									"DeliveryPersistent": ConnectorActionDescriptorPropertyDefinitionStepProperties{
										ComponentProperty: false,
										DefaultValue:      "true",
										Deprecated:        false,
										LabelHint:         "Message delivery is guaranteed when Persistent is selected.",
										DisplayName:       "Persistent",
										Group:             "producer",
										JavaType:          "boolean",
										Kind:              "parameter",
										Label:             "producer",
										Required:          false,
										Secret:            false,
										Type:              "boolean",
										Order:             3,
									},
								},
							},
						},
					},
					ActionType: "connector",
					Pattern:    "To",
				}, {
					ID:          "io.syndesis:amqp-subscribe-action",
					Name:        "Subscribe for messages",
					Description: "Receive data from the destination you specify.",
					Descriptor: ConnectorActionDescriptor{
						InputDataShape: ConnectorActionDescriptorDataShape{
							Kind: "none",
						},
						OutputDataShape: ConnectorActionDescriptorDataShape{
							Kind: "any",
						},
						PropertyDefinitionSteps: []ConnectorActionDescriptorPropertyDefinitionStep{
							{
								Description: "Specify AMQP destination properties, including Queue or Topic Name",
								Name:        "Select the AMQP Destination",
								Properties: map[string]ConnectorActionDescriptorPropertyDefinitionStepProperties{
									"DestinationName": ConnectorActionDescriptorPropertyDefinitionStepProperties{
										ComponentProperty: false,
										Deprecated:        false,
										LabelHint:         "Name of the queue or topic to receive data from.",
										DisplayName:       "Destination Name",
										Group:             "common",
										JavaType:          "java.lang.String",
										Kind:              "path",
										Required:          true,
										Secret:            false,
										Type:              "string",
										Order:             1,
									},
									"DestinationType": ConnectorActionDescriptorPropertyDefinitionStepProperties{
										ComponentProperty: false,
										DefaultValue:      "queue",
										Deprecated:        false,
										LabelHint:         "By default, the destination is a Queue.",
										DisplayName:       "Destination Type",
										Group:             "common",
										JavaType:          "java.lang.String",
										Kind:              "path",
										Required:          false,
										Secret:            false,
										Type:              "string",
										Order:             2,
										Enum: []ConnectorActionDescriptorPropertyEnum{
											{
												Label: "Topic",
												Value: "topic",
											},
											{
												Label: "Queue",
												Value: "queue",
											},
										},
									},
									"DurableSubscriptionId": ConnectorActionDescriptorPropertyDefinitionStepProperties{
										ComponentProperty: false,
										Deprecated:        false,
										LabelHint:         "Set the ID that lets connections close and reopen with missing messages. Connection type must be a topic.",
										DisplayName:       "Durable Subscription ID",
										Group:             "consumer",
										JavaType:          "java.lang.String",
										Kind:              "parameter",
										Label:             "consumer",
										Required:          false,
										Secret:            false,
										Type:              "string",
										Order:             3,
									},
									"MessageSelector": ConnectorActionDescriptorPropertyDefinitionStepProperties{
										ComponentProperty: false,
										Deprecated:        false,
										LabelHint:         "Specify a filter expression to receive only data that meets certain criteria.",
										DisplayName:       "Message Selector",
										Group:             "consumer (advanced)",
										JavaType:          "java.lang.String",
										Kind:              "parameter",
										Label:             "consumer,advanced",
										Required:          false,
										Secret:            false,
										Type:              "string",
										Order:             4,
									},
								},
							},
						},
					},
					ActionType: "connector",
					Pattern:    "From",
				}, {
					ID:          "io.syndesis:amqp-request-action",
					Name:        "Request response using messages",
					Description: "Send data to the destination you specify and receive a response.",
					Descriptor: ConnectorActionDescriptor{
						InputDataShape: ConnectorActionDescriptorDataShape{
							Kind: "any",
						},
						OutputDataShape: ConnectorActionDescriptorDataShape{
							Kind: "any",
						},
						PropertyDefinitionSteps: []ConnectorActionDescriptorPropertyDefinitionStep{
							{
								Description: "Specify AMQP destination properties, including Queue or Topic Name",
								Name:        "Select the AMQP Destination",
								Properties: map[string]ConnectorActionDescriptorPropertyDefinitionStepProperties{
									"DestinationName": ConnectorActionDescriptorPropertyDefinitionStepProperties{
										ComponentProperty: false,
										Deprecated:        false,
										LabelHint:         "Name of the queue or topic to receive data from.",
										DisplayName:       "Destination Name",
										Group:             "common",
										JavaType:          "java.lang.String",
										Kind:              "path",
										Required:          true,
										Secret:            false,
										Type:              "string",
										Order:             1,
									},
									"DestinationType": ConnectorActionDescriptorPropertyDefinitionStepProperties{
										ComponentProperty: false,
										DefaultValue:      "queue",
										Deprecated:        false,
										LabelHint:         "By default, the destination is a Queue.",
										DisplayName:       "Destination Type",
										Group:             "common",
										JavaType:          "java.lang.String",
										Kind:              "path",
										Required:          false,
										Secret:            false,
										Type:              "string",
										Order:             2,
										Enum: []ConnectorActionDescriptorPropertyEnum{
											{
												Label: "Topic",
												Value: "topic",
											},
											{
												Label: "Queue",
												Value: "queue",
											},
										},
									},
									"DurableSubscriptionId": ConnectorActionDescriptorPropertyDefinitionStepProperties{
										ComponentProperty: false,
										Deprecated:        false,
										LabelHint:         "Set the ID that lets connections close and reopen with missing messages. Connection type must be a topic.",
										DisplayName:       "Durable Subscription ID",
										Group:             "consumer",
										JavaType:          "java.lang.String",
										Kind:              "parameter",
										Label:             "consumer",
										Required:          false,
										Secret:            false,
										Type:              "string",
										Order:             3,
									},
									"MessageSelector": ConnectorActionDescriptorPropertyDefinitionStepProperties{
										ComponentProperty: false,
										Deprecated:        false,
										LabelHint:         "Specify a filter expression to receive only data that meets certain criteria.",
										DisplayName:       "Message Selector",
										Group:             "consumer (advanced)",
										JavaType:          "java.lang.String",
										Kind:              "parameter",
										Label:             "consumer,advanced",
										Required:          false,
										Secret:            false,
										Type:              "string",
										Order:             4,
									},
								},
							},
						},
					},
					ActionType: "connector",
					Pattern:    "To",
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(bodyBytes), nil
}

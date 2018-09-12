package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	glog "github.com/sirupsen/logrus"
	v1alpha1 "github.com/syndesisio/syndesis/install/operator/pkg/apis/syndesis/v1alpha1"
)

type Client interface {
	CreateConnection(connection *v1alpha1.Connection) error
}

type ConnectionCreatePost struct {
	ConfiguredProperties ConfiguredProperties `json:"configuredProperties"`
	Name                 string               `json:"name"`
	Description          string               `json:"description"`
	Connector            Connector            `json:"connector"`
	Icon                 string               `json:"icon"`
	ConnectorID          string               `json:"connectorId"`
}

type Connector struct {
	Tags             []string                     `json:"tags,omitempty"`
	Uses             int                          `json:"uses"`
	Description      string                       `json:"description"`
	Name             string                       `json:"name,omitempty"`
	Icon             string                       `json:"icon"`
	ComponentScheme  string                       `json:"componentScheme"`
	ConnectorFactory string                       `json:"connectorFactory"`
	ID               string                       `json:"id"`
	Version          int                          `json:"version"`
	Dependencies     []ConnectorDependency        `json:"dependencies"`
	Actions          []ConnectorAction            `json:"actions"`
	Properties       map[string]ConnectorProperty `json:"properties"`
	ActionsSummary   ConnectorActionsSummary      `json:"actionsSummary"`
}

type ConnectorActionsSummary struct {
	TotalActions int `json:"totalActions"`
}
type ConnectorAction struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Descriptor  ConnectorActionDescriptor `json:"descriptor"`
	ActionType  string                    `json:"actionType"`
	Pattern     string                    `json:"pattern"`
}

type ConnectorDataShape struct {
	Kind string `json:"kind"`
}

type ConnectorEnum struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type ConnectorStep struct {
	Description string                       `json:"description"`
	Name        string                       `json:"name"`
	Properties  map[string]ConnectorProperty `json:"properties"`
}

type ConnectorProperty struct {
	ComponentProperty bool                        `json:"componentProperty"`
	Deprecated        bool                        `json:"deprecated"`
	Description       string                      `json:"description,omitempty"`
	LabelHint         string                      `json:"labelHint,omitempty"`
	DisplayName       string                      `json:"displayName,omitempty"`
	Group             string                      `json:"group,omitempty"`
	JavaType          string                      `json:"javaType,omitempty"`
	Kind              string                      `json:"kind,omitempty"`
	Label             string                      `json:"label,omitempty"`
	Required          bool                        `json:"required"`
	Secret            bool                        `json:"secret"`
	Type              string                      `json:"type,omitempty"`
	Order             int                         `json:"order,omitempty"`
	Relation          []ConnectorPropertyRelation `json:"relation,omitempty"`
	Enum              []ConnectorEnum             `json:"enum,omitempty"`
	DefaultValue      string                      `json:"defaultValue,omitempty"`
}

type ConnectorPropertyEvent struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

type ConnectorPropertyRelation struct {
	Action string                   `json:"action"`
	When   []ConnectorPropertyEvent `json:"when"`
}

type ConnectorActionDescriptor struct {
	InputDataShape          ConnectorDataShape `json:"inputDataShape"`
	OutputDataShape         ConnectorDataShape `json:"outputDataShape"`
	PropertyDefinitionSteps []ConnectorStep    `json:"propertyDefinitionSteps"`
}

type ConnectorDependency struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}
type ConfiguredProperties struct {
	ConnectionURI        string `json:"connectionUri"`
	Username             string `json:"username"`
	Password             string `json:"password"`
	SkipCertificateCheck string `json:"skipCertificateCheck"`
	BrokerCertificate    string `json:"brokerCertificate,omitempty"`
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
		Name: connectionName,
		ConfiguredProperties: ConfiguredProperties{
			SkipCertificateCheck: "true",
			ConnectionURI:        url,
			Username:             username,
			Password:             password,
		},
		Connector: Connector{
			Description:      "Subscribe for and publish messages.",
			Icon:             "fa-amqp",
			ComponentScheme:  "amqp",
			ConnectorFactory: "io.syndesis.connector.amqp.AMQPConnectorFactory",
			Tags: []string{
				"verifier",
			},
			Uses: 0,
			ActionsSummary: ConnectorActionsSummary{
				TotalActions: 3,
			},
			ID:      "amqp",
			Version: 3,
			Actions: []ConnectorAction{
				{
					ID:          "io.syndesis:amqp-publish-action",
					Name:        "Publish messages",
					Description: "Send data to the destination you specify.",
					Descriptor: ConnectorActionDescriptor{
						InputDataShape: ConnectorDataShape{
							Kind: "any",
						},
						OutputDataShape: ConnectorDataShape{
							Kind: "none",
						},
						PropertyDefinitionSteps: []ConnectorStep{
							{
								Description: "Specify AMQP destination properties, including Queue or Topic name",
								Name:        "Select the AMQP Destination",
								Properties: map[string]ConnectorProperty{
									"destinationName": ConnectorProperty{
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
									"destinationType": ConnectorProperty{
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
										Enum: []ConnectorEnum{
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
									"deliveryPersistent": ConnectorProperty{
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
						InputDataShape: ConnectorDataShape{
							Kind: "none",
						},
						OutputDataShape: ConnectorDataShape{
							Kind: "any",
						},
						PropertyDefinitionSteps: []ConnectorStep{
							{
								Description: "Specify AMQP destination properties, including Queue or Topic Name",
								Name:        "Select the AMQP Destination",
								Properties: map[string]ConnectorProperty{
									"destinationName": ConnectorProperty{
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
									"destinationType": ConnectorProperty{
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
										Enum: []ConnectorEnum{
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
									"durableSubscriptionId": ConnectorProperty{
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
									"messageSelector": ConnectorProperty{
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
						InputDataShape: ConnectorDataShape{
							Kind: "any",
						},
						OutputDataShape: ConnectorDataShape{
							Kind: "any",
						},
						PropertyDefinitionSteps: []ConnectorStep{
							{
								Description: "Specify AMQP destination properties, including Queue or Topic Name",
								Name:        "Select the AMQP Destination",
								Properties: map[string]ConnectorProperty{
									"destinationName": ConnectorProperty{
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
									"destinationType": ConnectorProperty{
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
										Enum: []ConnectorEnum{
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
									"durableSubscriptionId": ConnectorProperty{
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
									"messageSelector": ConnectorProperty{
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
			Name: "AMQP Message Broker",
			Properties: map[string]ConnectorProperty{
				"connectionUri": ConnectorProperty{
					ComponentProperty: true,
					Deprecated:        false,
					LabelHint:         "Location to send data to or obtain data from.",
					DisplayName:       "Connection URI",
					Group:             "common",
					JavaType:          "java.lang.String",
					Kind:              "property",
					Label:             "common",
					Required:          true,
					Secret:            false,
					Type:              "string",
					Order:             1,
				},
				"username": ConnectorProperty{
					ComponentProperty: true,
					Deprecated:        false,
					LabelHint:         "Access the broker with this user’s authorization credentials.",
					DisplayName:       "User Name",
					Group:             "security",
					JavaType:          "java.lang.String",
					Kind:              "property",
					Label:             "common,security",
					Required:          false,
					Secret:            false,
					Type:              "string",
					Order:             2,
				},
				"password": ConnectorProperty{
					ComponentProperty: true,
					Deprecated:        false,
					LabelHint:         "Password for the specified user account.",
					DisplayName:       "Password",
					Group:             "security",
					JavaType:          "java.lang.String",
					Kind:              "property",
					Label:             "common,security",
					Required:          false,
					Secret:            true,
					Type:              "string",
					Order:             3,
				},
				"clientID": ConnectorProperty{
					ComponentProperty: true,
					Deprecated:        false,
					LabelHint:         "Required for connections to close and reopen without missing messages. Connection destination must be a topic.",
					DisplayName:       "Client ID",
					Group:             "security",
					JavaType:          "java.lang.String",
					Kind:              "property",
					Label:             "common,security",
					Required:          false,
					Secret:            false,
					Type:              "string",
					Order:             4,
				},
				"skipCertificateCheck": ConnectorProperty{
					ComponentProperty: true,
					DefaultValue:      "false",
					Deprecated:        false,
					LabelHint:         "Ensure certificate checks are enabled for secure production environments. Disable for convenience in only development environments.",
					DisplayName:       "Check Certificates",
					Group:             "security",
					JavaType:          "java.lang.String",
					Kind:              "property",
					Label:             "common,security",
					Required:          false,
					Secret:            false,
					Type:              "string",
					Order:             5,
					Enum: []ConnectorEnum{
						{
							Label: "Disable",
							Value: "true",
						},
						{
							Label: "Enable",
							Value: "false",
						},
					},
				},
				"brokerCertificate": ConnectorProperty{
					ComponentProperty: true,
					Deprecated:        false,
					Description:       "AMQ Broker X.509 PEM Certificate",
					DisplayName:       "Broker Certificate",
					Group:             "security",
					JavaType:          "java.lang.String",
					Kind:              "property",
					Label:             "common,security",
					Required:          false,
					Secret:            false,
					Type:              "textarea",
					Order:             6,
					Relation: []ConnectorPropertyRelation{
						{
							Action: "ENABLE",
							When: []ConnectorPropertyEvent{
								{
									ID:    "skipCertificateCheck",
									Value: "false",
								},
							},
						},
					},
				},
				"clientCertificate": ConnectorProperty{
					ComponentProperty: true,
					Deprecated:        false,
					Description:       "AMQ Client X.509 PEM Certificate",
					DisplayName:       "Client Certificate",
					Group:             "security",
					JavaType:          "java.lang.String",
					Kind:              "property",
					Label:             "common,security",
					Required:          false,
					Secret:            false,
					Type:              "textarea",
					Order:             7,
					Relation: []ConnectorPropertyRelation{
						{
							Action: "ENABLE",
							When: []ConnectorPropertyEvent{
								{
									ID:    "skipCertificateCheck",
									Value: "false",
								},
							},
						},
					},
				},
			},
			Dependencies: []ConnectorDependency{
				{
					Type: "MAVEN",
					ID:   "io.syndesis.connector:connector-amqp:1.5-SNAPSHOT",
				},
			},
		},
		Icon:        "fa-amqp",
		ConnectorID: "amqp",
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(bodyBytes), nil
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/option"
)

var (
	// Required scopes for Cloud Identity and Admin Directory APIs
	requiredScopes = []string{
		"https://www.googleapis.com/auth/cloud-identity.groups",
		"https://www.googleapis.com/auth/admin.directory.group",
		"https://www.googleapis.com/auth/admin.directory.group.member",
	}
)

type ServiceConfig struct {
	ServiceAccountKeyPath string
	DelegatedUser         string
	CustomerID            string
}

func NewServiceConfig(keyPath, delegatedUser, customerID string) (*ServiceConfig, error) {
	absPath, err := filepath.Abs(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve key path: %v", err)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("service account key file does not exist: %s", absPath)
	}

	return &ServiceConfig{
		ServiceAccountKeyPath: absPath,
		DelegatedUser:         delegatedUser,
		CustomerID:            customerID,
	}, nil
}

func CreateServiceWithoutDelegation(ctx context.Context, config *ServiceConfig) (*cloudidentity.Service, error) {
	service, err := cloudidentity.NewService(ctx,
		option.WithCredentialsFile(config.ServiceAccountKeyPath),
		option.WithScopes("https://www.googleapis.com/auth/cloud-identity.groups"))

	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Identity service: %v", err)
	}
	return service, nil
}

func CreateServiceWithDelegation(ctx context.Context, config *ServiceConfig) (*cloudidentity.Service, error) {
	if config.DelegatedUser == "" {
		return nil, fmt.Errorf("delegated user is required for delegation")
	}

	data, err := os.ReadFile(config.ServiceAccountKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials: %v", err)
	}

	jwtConfig, err := google.JWTConfigFromJSON(data, requiredScopes...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service account key: %v", err)
	}

	jwtConfig.Subject = config.DelegatedUser
	client := jwtConfig.Client(ctx)

	service, err := cloudidentity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud identity service: %v", err)
	}

	return service, nil
}

func ListGroups(ctx context.Context, service *cloudidentity.Service, customerID string, pageSize int64) error {
	parent := fmt.Sprintf("customers/%s", customerID)
	resp, err := service.Groups.List().Parent(parent).View("BASIC").PageSize(pageSize).Do()
	if err != nil {
		return fmt.Errorf("failed to list groups: %v", err)
	}

	for _, group := range resp.Groups {
		fmt.Printf("Group: %s\n", group.DisplayName)
	}
	return nil
}

func verifyServiceAccount(data []byte) error {
	var serviceAccount struct {
		ClientEmail string `json:"client_email"`
		ProjectID   string `json:"project_id"`
	}
	if err := json.Unmarshal(data, &serviceAccount); err != nil {
		return fmt.Errorf("failed to parse service account JSON: %v", err)
	}

	fmt.Printf("Service Account Email: %s\n", serviceAccount.ClientEmail)
	fmt.Printf("Project ID: %s\n", serviceAccount.ProjectID)
	return nil
}

func main() {
	ctx := context.Background()

	config, err := NewServiceConfig(
		"/Users/yhuang/workspace/learning/.private/instastructure-20250127-abbe522c360e.json",
		"jimmy.huang@instructurelab.com",
		"C03ygpcl8", // Replace with your actual Customer ID
	)
	if err != nil {
		log.Fatalf("Failed to create service config: %v", err)
	}

	// Add token verification step
	if err := verifyTokenAccess(ctx, config); err != nil {
		log.Fatalf("Failed to verify token access: %v", err)
	}
	fmt.Println("Token verification successful")

	// Example 1: Create service without delegation
	serviceWithoutDelegation, err := CreateServiceWithoutDelegation(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create service without delegation: %v", err)
	}
	fmt.Println("Successfully created service without delegation")

	// List groups using the delegated service
	if err := ListGroups(ctx, serviceWithoutDelegation, config.CustomerID, 10); err != nil {
		log.Fatalf("Failed to list groups: %v", err)
	}

	// Example 2: Create service with delegation
	serviceWithDelegation, err := CreateServiceWithDelegation(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create service with delegation: %v", err)
	}
	fmt.Println("Successfully created service with delegation")

	// List groups using the delegated service
	if err := ListGroups(ctx, serviceWithDelegation, config.CustomerID, 10); err != nil {
		log.Fatalf("Failed to list groups: %v", err)
	}
}

func verifyTokenAccess(ctx context.Context, config *ServiceConfig) error {
	// First read and verify the service account file
	data, err := os.ReadFile(config.ServiceAccountKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read credentials: %v", err)
	}

	// Print service account details for verification
	var serviceAccount struct {
		ClientEmail string `json:"client_email"`
		ProjectID   string `json:"project_id"`
	}
	if err := json.Unmarshal(data, &serviceAccount); err != nil {
		return fmt.Errorf("failed to parse service account JSON: %v", err)
	}
	fmt.Printf("Attempting authentication with:\n")
	fmt.Printf("- Service Account: %s\n", serviceAccount.ClientEmail)
	fmt.Printf("- Project ID: %s\n", serviceAccount.ProjectID)
	fmt.Printf("- Delegated User: %s\n", config.DelegatedUser)
	fmt.Printf("- Requested Scopes: %v\n", requiredScopes)

	jwtConfig, err := google.JWTConfigFromJSON(data, requiredScopes...)
	if err != nil {
		return fmt.Errorf("failed to parse service account key: %v", err)
	}

	if config.DelegatedUser != "" {
		jwtConfig.Subject = config.DelegatedUser
		fmt.Printf("Using delegation with subject: %s\n", config.DelegatedUser)
	}

	token, err := jwtConfig.TokenSource(ctx).Token()
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	} else {
		fmt.Printf("Token acquired successfully\n")
		fmt.Printf("Token: %s\n", token.AccessToken)
	}

	return nil
}

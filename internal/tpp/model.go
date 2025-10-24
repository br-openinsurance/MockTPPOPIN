package tpp

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

type Session struct {
	ID              string   `json:"id"`
	UserID          string   `json:"user_id"`
	IsAdmin         bool     `json:"is_admin"`
	OrganizationIDs []string `json:"org_ids"`
	CodeVerifier    string   `json:"code_verifier"`

	CreatedAt int `json:"created_at"`
	ExpiresAt int `json:"expires_at"`
}

func (s *Session) TableName() string {
	return "sessions"
}

func (s *Session) IsExpired() bool {
	return s.ExpiresAt < timestampNow()
}

type Flow struct {
	ID           string  `json:"id"`
	UserID       string  `json:"user_id"`
	APIType      APIType `json:"api_type"`
	APIVersion   string  `json:"api_version"`
	AuthServerID string  `json:"auth_server_id"`
	ClientID     string  `json:"client_id"`
	OrgID        string  `json:"org_id"`

	CodeVerifier  string `json:"code_verifier"`
	AuthCodeToken string `json:"auth_code_token"`
}

func (f *Flow) TableName() string {
	return "flows"
}

type Client struct {
	AuthServerID      string `json:"id"`
	ClientID          string `json:"client_id"`
	RegistrationToken string `json:"registration_token"`
	CreatedAt         int    `json:"created_at"`
}

func (c *Client) TableName() string {
	return "clients"
}

type Log struct {
	ID        string         `json:"id"`
	FlowID    string         `json:"flow_id"`
	Message   string         `json:"message"`
	Args      map[string]any `json:"args"`
	CreatedAt int            `json:"created_at"`
}

func (s *Log) TableName() string {
	return "logs"
}

type Logs []*Log

func (l *Logs) TableName() string {
	return "logs"
}

type OpenIDConfiguration struct {
	Issuer         string                    `json:"issuer"`
	AuthEndpoint   string                    `json:"authorization_endpoint"`
	JWKSURI        string                    `json:"jwks_uri"`
	TokenEndpoint  string                    `json:"token_endpoint"`
	IDTokenSigAlgs []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported"`
	MTLS           struct {
		PushedAuthEndpoint   string `json:"pushed_authorization_request_endpoint"`
		TokenEndpoint        string `json:"token_endpoint"`
		RegistrationEndpoint string `json:"registration_endpoint"`
	} `json:"mtls_endpoint_aliases"`
}

type Participant struct {
	OrgID       string       `json:"OrganisationId"`
	Name        string       `json:"OrganisationName"`
	AuthServers []AuthServer `json:"AuthorisationServers"`
}

type AuthServer struct {
	ID              string `json:"AuthorisationServerId"`
	OrgID           string `json:"OrganisationId"`
	Name            string `json:"CustomerFriendlyName"`
	OpenIDConfigURL string `json:"OpenIDDiscoveryDocument"`
	Resources       []struct {
		APIType            APIType `json:"ApiFamilyType"`
		Version            string  `json:"ApiVersion"`
		Status             string  `json:"Status"`
		DiscoveryEndpoints []struct {
			Endpoint string `json:"ApiEndpoint"`
		} `json:"ApiDiscoveryEndpoints"`
	} `json:"ApiResources"`
}

func (a AuthServer) ResourceHost(apiType APIType, apiVersion string) (string, error) {
	for _, resource := range a.Resources {
		if resource.APIType == apiType && strings.HasPrefix(resource.Version, apiVersion) {
			uri, err := url.Parse(resource.DiscoveryEndpoints[0].Endpoint)
			if err != nil {
				return "", fmt.Errorf("failed to parse resource host: %w", err)
			}
			return "https://" + uri.Host, nil
		}
	}
	return "", errors.New("resource not found")
}

type APIType string

const (
	APITypeConsents                    APIType = "consents"
	APITypeCustomersPersonal           APIType = "customers-personal"
	APITypeCustomersBusiness           APIType = "customers-business"
	APITypeAuto                        APIType = "auto"
	APITypeHousing                     APIType = "housing"
	APITypeAcceptanceAndBranchesAbroad APIType = "acceptance-and-branches-abroad"
	APITypeCapitalizationTitle         APIType = "insurance-capitalization-title"
	APITypeFinancialAssistance         APIType = "insurance-financial-assistance"
)

func (t APIType) String() string {
	return string(t)
}

func (t APIType) Scope() string {
	switch t {
	case APITypeCustomersPersonal:
		return "customers"
	case APITypeCustomersBusiness:
		return "customers"
	case APITypeAuto:
		return "insurance-auto"
	case APITypeHousing:
		return "insurance-housing"
	case APITypeAcceptanceAndBranchesAbroad:
		return "insurance-acceptance-and-branches-abroad"
	case APITypeCapitalizationTitle:
		return "capitalization-title"
	case APITypeFinancialAssistance:
		return "insurance-financial-assistance"
	}

	return ""
}

type Permission string

const (
	PermissionResourcesRead                                             Permission = "RESOURCES_READ"
	PermissionCustomersPersonalIdentificationsRead                      Permission = "CUSTOMERS_PERSONAL_IDENTIFICATIONS_READ"
	PermissionCustomersPersonalAdditionalInfoRead                       Permission = "CUSTOMERS_PERSONAL_ADDITIONALINFO_READ"
	PermissionCustomersPersonalQualificationRead                        Permission = "CUSTOMERS_PERSONAL_QUALIFICATION_READ"
	PermissionCustomersBusinessIdentificationsRead                      Permission = "CUSTOMERS_BUSINESS_IDENTIFICATIONS_READ"
	PermissionCustomersBusinessAdditionalInfoRead                       Permission = "CUSTOMERS_BUSINESS_QUALIFICATION_READ"
	PermissionCustomersBusinessQualificationRead                        Permission = "CUSTOMERS_BUSINESS_ADDITIONALINFO_READ"
	PermissionDamagesAndPeopleAutoRead                                  Permission = "DAMAGES_AND_PEOPLE_AUTO_READ"
	PermissionDamagesAndPeopleAutoPolicyInfoRead                        Permission = "DAMAGES_AND_PEOPLE_AUTO_POLICYINFO_READ"
	PermissionDamagesAndPeopleAutoPremiumRead                           Permission = "DAMAGES_AND_PEOPLE_AUTO_PREMIUM_READ"
	PermissionDamagesAndPeopleAutoClaimRead                             Permission = "DAMAGES_AND_PEOPLE_AUTO_CLAIM_READ"
	PermissionDamagesAndPeopleHousingRead                               Permission = "DAMAGES_AND_PEOPLE_HOUSING_READ"
	PermissionDamagesAndPeopleHousingPolicyinfoRead                     Permission = "DAMAGES_AND_PEOPLE_HOUSING_POLICYINFO_READ"
	PermissionDamagesAndPeopleHousingPremiumRead                        Permission = "DAMAGES_AND_PEOPLE_HOUSING_PREMIUM_READ"
	PermissionDamagesAndPeopleHousingClaimRead                          Permission = "DAMAGES_AND_PEOPLE_HOUSING_CLAIM_READ"
	PermissionDamagesAndPeopleAcceptanceAndBranchesAbroadRead           Permission = "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_READ"
	PermissionDamagesAndPeopleAcceptanceAndBranchesAbroadPolicyinfoRead Permission = "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_POLICYINFO_READ"
	PermissionDamagesAndPeopleAcceptanceAndBranchesAbroadPremiumRead    Permission = "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_PREMIUM_READ"
	PermissionDamagesAndPeopleAcceptanceAndBranchesAbroadClaimRead      Permission = "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_CLAIM_READ"
	PermissionCapitalizationTitleRead                                   Permission = "CAPITALIZATION_TITLE_READ"
	PermissionCapitalizationTitlePlanInfoRead                           Permission = "CAPITALIZATION_TITLE_PLANINFO_READ"
	PermissionCapitalizationTitleEventsRead                             Permission = "CAPITALIZATION_TITLE_EVENTS_READ"
	PermissionCapitalizationTitleSettlementsRead                        Permission = "CAPITALIZATION_TITLE_SETTLEMENTS_READ"
	PermissionFinancialAssistanceRead                                   Permission = "FINANCIAL_ASSISTANCE_READ"
	PermissionFinancialAssistanceContractInfoRead                       Permission = "FINANCIAL_ASSISTANCE_CONTRACTINFO_READ"
	PermissionFinancialAssistanceMovementsRead                          Permission = "FINANCIAL_ASSISTANCE_MOVEMENTS_READ"
)

type Consent struct {
	UserCPF      string
	BusinessCNPJ string
	Permissions  []Permission
}

type IDToken struct {
	Sub     string `json:"sub"`
	Nonce   string `json:"nonce"`
	Profile struct {
		OrgAccessDetails map[string]struct {
			Name    string `json:"organisation_name"`
			IsAdmin bool   `json:"org_admin"`
		} `json:"org_access_details"`
	} `json:"trust_framework_profile"`
}

type tokenResponse struct {
	IDToken string `json:"id_token"`
	Token   string `json:"access_token"`
}

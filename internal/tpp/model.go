package tpp

import (
	"errors"
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
	ConsentID    string  `json:"consent_id"`
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
	Issuer             string                    `json:"issuer"`
	AuthEndpoint       string                    `json:"authorization_endpoint"`
	EndSessionEndpoint string                    `json:"end_session_endpoint"`
	JWKSURI            string                    `json:"jwks_uri"`
	TokenEndpoint      string                    `json:"token_endpoint"`
	IDTokenSigAlgs     []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported"`
	MTLS               struct {
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

func (a AuthServer) ResourceBaseURL(apiType APIType, apiVersion string) (string, error) {
	for _, resource := range a.Resources {
		if resource.APIType == apiType && strings.HasPrefix(resource.Version, apiVersion) {
			return strings.Split(resource.DiscoveryEndpoints[0].Endpoint, "/open-insurance")[0], nil
		}
	}
	return "", errors.New("resource not found")
}

type APIType string

const (
	APITypeResources                        APIType = "resources"
	APITypeConsents                         APIType = "consents"
	APITypeCustomersPersonal                APIType = "customers-personal"
	APITypeCustomersBusiness                APIType = "customers-business"
	APITypeAuto                             APIType = "auto"
	APITypeHousing                          APIType = "housing"
	APITypePatrimonial                      APIType = "patrimonial"
	APITypePerson                           APIType = "insurance-person"
	APITypeAcceptanceAndBranchesAbroad      APIType = "acceptance-and-branches-abroad"
	APITypeCapitalizationTitle              APIType = "insurance-capitalization-title"
	APITypeFinancialAssistance              APIType = "insurance-financial-assistance"
	APITypeFinancialRisk                    APIType = "financial-risk"
	APITypeLifePension                      APIType = "insurance-life-pension"
	APITypePensionPlan                      APIType = "insurance-pension-plan"
	APITypeTransport                        APIType = "transport"
	APITypeResponsibility                   APIType = "responsibility"
	APITypeRural                            APIType = "rural"
	APITypeQuoteAuto                        APIType = "quote-auto"
	APITypeQuoteAcceptanceAndBranchesAbroad APIType = "quote-acceptance-and-branches-abroad"
	APITypeQuotePatrimonialBusiness         APIType = "quote-patrimonial-business"
	APITypeQuotePatrimonialCondominium      APIType = "quote-patrimonial-condominium"
	APITypeQuotePatrimonialHome             APIType = "quote-patrimonial-home"
	APITypeQuotePatrimonialDiverseRisks     APIType = "quote-patrimonial-diverse-risks"
	APITypeQuoteHousing                     APIType = "quote-housing"
	APITypeQuoteFinancialRisk               APIType = "quote-financial-risk"
	APITypeQuoteResponsibility              APIType = "quote-responsibility"
	APITypeQuoteRural                       APIType = "quote-rural"
	APITypeQuoteTransport                   APIType = "quote-transport"
	APITypeQuotePersonLife                  APIType = "quote-person-life"
	APITypeQuotePersonTravel                APIType = "quote-person-travel"
	APITypeQuoteCapitalizationTitle         APIType = "quote-capitalization-title"
	// APITypeQuoteCapitalizationTitleRaffle is not registered in the directory, it is used to create a quote capitalization title raffle.
	APITypeQuoteCapitalizationTitleRaffle APIType = "quote-capitalization-title-raffle"
	APITypeContractLifePension            APIType = "contract-life-pension"
	APITypeDynamicFields                  APIType = "dynamic-fields"
	APITypeEndorsement                    APIType = "endorsement"
	APITypeClaimNotificationDamages       APIType = "claim-notification-damages"
	APITypeClaimNotificationPerson        APIType = "claim-notification-person"
	APITypeWithdrawalCapitalizationTitle  APIType = "withdrawal-capitalization-title"
	APITypeWithdrawalPension              APIType = "withdrawal-pension"
)

func (t APIType) String() string {
	return string(t)
}

// nolint:cyclop
func (t APIType) Scope() string {
	switch t {
	case APITypeResources:
		return "resources"
	case APITypeCustomersPersonal:
		return "customers"
	case APITypeCustomersBusiness:
		return "customers"
	case APITypeAuto:
		return "insurance-auto"
	case APITypeHousing:
		return "insurance-housing"
	case APITypePatrimonial:
		return "insurance-patrimonial"
	case APITypePerson:
		return "insurance-person"
	case APITypeAcceptanceAndBranchesAbroad:
		return "insurance-acceptance-and-branches-abroad"
	case APITypeCapitalizationTitle:
		return "capitalization-title"
	case APITypeFinancialAssistance:
		return "insurance-financial-assistance"
	case APITypeFinancialRisk:
		return "insurance-financial-risk"
	case APITypeLifePension:
		return "insurance-life-pension"
	case APITypePensionPlan:
		return "insurance-pension-plan"
	case APITypeTransport:
		return "insurance-transport"
	case APITypeRural:
		return "insurance-rural"
	case APITypeResponsibility:
		return "insurance-responsibility"
	case APITypeQuoteAuto:
		return "quote-auto quote-auto-lead"
	case APITypeQuoteAcceptanceAndBranchesAbroad:
		return "quote-acceptance-and-branches-abroad-lead"
	case APITypeQuotePatrimonialBusiness:
		return "quote-patrimonial-business quote-patrimonial-lead"
	case APITypeQuotePatrimonialCondominium:
		return "quote-patrimonial-condominium quote-patrimonial-lead"
	case APITypeQuotePatrimonialHome:
		return "quote-patrimonial-home quote-patrimonial-lead"
	case APITypeQuotePatrimonialDiverseRisks:
		return "quote-patrimonial-diverse-risks quote-patrimonial-lead"
	case APITypeQuoteHousing:
		return "quote-housing-lead"
	case APITypeQuoteFinancialRisk:
		return "quote-financial-risk-lead"
	case APITypeQuoteResponsibility:
		return "quote-responsibility-lead"
	case APITypeQuoteRural:
		return "quote-rural-lead"
	case APITypeQuoteTransport:
		return "quote-transport-lead"
	case APITypeQuotePersonLife:
		return "quote-person-life quote-person-lead"
	case APITypeQuotePersonTravel:
		return "quote-person-travel quote-person-lead"
	case APITypeQuoteCapitalizationTitle:
		return "quote-capitalization-title quote-capitalization-title-lead quote-capitalization-title-raffle"
	case APITypeQuoteCapitalizationTitleRaffle:
		return "quote-capitalization-title-raffle"
	case APITypeContractLifePension:
		return "contract-life-pension contract-life-pension-lead"
	case APITypeDynamicFields:
		return "dynamic-fields"
	case APITypeEndorsement:
		return "endorsement"
	case APITypeClaimNotificationDamages, APITypeClaimNotificationPerson:
		return "claim-notification"
	case APITypeWithdrawalCapitalizationTitle:
		return "withdrawal-capitalization-title"
	case APITypeWithdrawalPension:
		return "withdrawal-pension withdrawal-pension-lead"
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
	PermissionDamagesAndPeoplePatrimonialRead                           Permission = "DAMAGES_AND_PEOPLE_PATRIMONIAL_READ"
	PermissionDamagesAndPeoplePatrimonialPolicyinfoRead                 Permission = "DAMAGES_AND_PEOPLE_PATRIMONIAL_POLICYINFO_READ"
	PermissionDamagesAndPeoplePatrimonialPremiumRead                    Permission = "DAMAGES_AND_PEOPLE_PATRIMONIAL_PREMIUM_READ"
	PermissionDamagesAndPeoplePatrimonialClaimRead                      Permission = "DAMAGES_AND_PEOPLE_PATRIMONIAL_CLAIM_READ"
	PermissionDamagesAndPeoplePersonRead                                Permission = "DAMAGES_AND_PEOPLE_PERSON_READ"
	PermissionDamagesAndPeoplePersonPolicyinfoRead                      Permission = "DAMAGES_AND_PEOPLE_PERSON_POLICYINFO_READ"
	PermissionDamagesAndPeoplePersonPremiumRead                         Permission = "DAMAGES_AND_PEOPLE_PERSON_PREMIUM_READ"
	PermissionDamagesAndPeoplePersonClaimRead                           Permission = "DAMAGES_AND_PEOPLE_PERSON_CLAIM_READ"
	PermissionDamagesAndPeopleAcceptanceAndBranchesAbroadRead           Permission = "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_READ"
	PermissionDamagesAndPeopleAcceptanceAndBranchesAbroadPolicyinfoRead Permission = "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_POLICYINFO_READ"
	PermissionDamagesAndPeopleAcceptanceAndBranchesAbroadPremiumRead    Permission = "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_PREMIUM_READ"
	PermissionDamagesAndPeopleAcceptanceAndBranchesAbroadClaimRead      Permission = "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_CLAIM_READ"
	PermissionDamagesAndPeopleTransportRead                             Permission = "DAMAGES_AND_PEOPLE_TRANSPORT_READ"
	PermissionDamagesAndPeopleTransportPolicyinfoRead                   Permission = "DAMAGES_AND_PEOPLE_TRANSPORT_POLICYINFO_READ"
	PermissionDamagesAndPeopleTransportPremiumRead                      Permission = "DAMAGES_AND_PEOPLE_TRANSPORT_PREMIUM_READ"
	PermissionDamagesAndPeopleTransportClaimRead                        Permission = "DAMAGES_AND_PEOPLE_TRANSPORT_CLAIM_READ"
	PermissionDamagesAndPeopleRuralRead                                 Permission = "DAMAGES_AND_PEOPLE_RURAL_READ"
	PermissionDamagesAndPeopleRuralPolicyinfoRead                       Permission = "DAMAGES_AND_PEOPLE_RURAL_POLICYINFO_READ"
	PermissionDamagesAndPeopleRuralPremiumRead                          Permission = "DAMAGES_AND_PEOPLE_RURAL_PREMIUM_READ"
	PermissionDamagesAndPeopleRuralClaimRead                            Permission = "DAMAGES_AND_PEOPLE_RURAL_CLAIM_READ"
	PermissionDamagesAndPeopleResponsibilityRead                        Permission = "DAMAGES_AND_PEOPLE_RESPONSIBILITY_READ"
	PermissionDamagesAndPeopleResponsibilityPolicyinfoRead              Permission = "DAMAGES_AND_PEOPLE_RESPONSIBILITY_POLICYINFO_READ"
	PermissionDamagesAndPeopleResponsibilityPremiumRead                 Permission = "DAMAGES_AND_PEOPLE_RESPONSIBILITY_PREMIUM_READ"
	PermissionDamagesAndPeopleResponsibilityClaimRead                   Permission = "DAMAGES_AND_PEOPLE_RESPONSIBILITY_CLAIM_READ"
	PermissionDamagesAndPeopleFinancialRiskRead                         Permission = "DAMAGES_AND_PEOPLE_FINANCIAL_RISKS_READ"
	PermissionDamagesAndPeopleFinancialRiskPolicyinfoRead               Permission = "DAMAGES_AND_PEOPLE_FINANCIAL_RISKS_POLICYINFO_READ"
	PermissionDamagesAndPeopleFinancialRiskPremiumRead                  Permission = "DAMAGES_AND_PEOPLE_FINANCIAL_RISKS_PREMIUM_READ"
	PermissionDamagesAndPeopleFinancialRiskClaimRead                    Permission = "DAMAGES_AND_PEOPLE_FINANCIAL_RISKS_CLAIM_READ"
	PermissionCapitalizationTitleRead                                   Permission = "CAPITALIZATION_TITLE_READ"
	PermissionCapitalizationTitlePlanInfoRead                           Permission = "CAPITALIZATION_TITLE_PLANINFO_READ"
	PermissionCapitalizationTitleEventsRead                             Permission = "CAPITALIZATION_TITLE_EVENTS_READ"
	PermissionCapitalizationTitleSettlementsRead                        Permission = "CAPITALIZATION_TITLE_SETTLEMENTS_READ"
	PermissionFinancialAssistanceRead                                   Permission = "FINANCIAL_ASSISTANCE_READ"
	PermissionFinancialAssistanceContractInfoRead                       Permission = "FINANCIAL_ASSISTANCE_CONTRACTINFO_READ"
	PermissionFinancialAssistanceMovementsRead                          Permission = "FINANCIAL_ASSISTANCE_MOVEMENTS_READ"
	PermissionLifePensionRead                                           Permission = "LIFE_PENSION_READ"
	PermissionLifePensionContractInfoRead                               Permission = "LIFE_PENSION_CONTRACTINFO_READ"
	PermissionLifePensionMovementsRead                                  Permission = "LIFE_PENSION_MOVEMENTS_READ"
	PermissionLifePensionPortabilitiesRead                              Permission = "LIFE_PENSION_PORTABILITIES_READ"
	PermissionLifePensionWithdrawalsRead                                Permission = "LIFE_PENSION_WITHDRAWALS_READ"
	PermissionLifePensionClaim                                          Permission = "LIFE_PENSION_CLAIM"
	PermissionPensionPlanRead                                           Permission = "PENSION_PLAN_READ"
	PermissionPensionPlanContractInfoRead                               Permission = "PENSION_PLAN_CONTRACTINFO_READ"
	PermissionPensionPlanMovementsRead                                  Permission = "PENSION_PLAN_MOVEMENTS_READ"
	PermissionPensionPlanPortabilitiesRead                              Permission = "PENSION_PLAN_PORTABILITIES_READ"
	PermissionPensionPlanWithdrawalsRead                                Permission = "PENSION_PLAN_WITHDRAWALS_READ"
	PermissionPensionPlanClaim                                          Permission = "PENSION_PLAN_CLAIM"
)

type Consent struct {
	UserCPF                        string
	BusinessCNPJ                   string
	Permissions                    []Permission
	Endorsement                    *Endorsement
	ClaimNotification              *ClaimNotification
	WithdrawalLifePension          *WithdrawalLifePension
	WithdrawalCapitalizationTitle  *WithdrawalCapitalizationTitle
	QuoteCapitalizationTitleRaffle *QuoteCapitalizationTitleRaffle
}

type Endorsement struct {
	PolicyID           string   `json:"policyId"`
	InsuredObjectID    []string `json:"insuredObjectId"`
	Type               string   `json:"endorsementType"`
	ProposalID         string   `json:"proposalId,omitempty"`
	RequestDescription string   `json:"requestDescription"`
}

type ClaimNotification struct {
	DocumentType          string   `json:"documentType"`
	PolicyID              string   `json:"policyId"`
	GroupCertificateID    string   `json:"groupCertificateId,omitempty"`
	InsuredObjectID       []string `json:"insuredObjectId"`
	ProposalID            string   `json:"proposalId,omitempty"`
	OccurrenceDate        string   `json:"occurrenceDate"`
	OccurrenceTime        string   `json:"occurrenceTime,omitempty"`
	OccurrenceDescription string   `json:"occurrenceDescription"`
}

type WithdrawalLifePension struct {
	CertificateID          string `json:"certificateId"`
	ProductName            string `json:"productName"`
	WithdrawalType         string `json:"withdrawalType"`
	WithdrawalReason       string `json:"withdrawalReason"`
	WithdrawalReasonOthers string `json:"withdrawalReasonOthers,omitempty"`
	DesiredTotalAmount     string `json:"desiredTotalAmount,omitempty"`
	PmbacAmount            string `json:"pmbacAmount,omitempty"`
}

type WithdrawalCapitalizationTitle struct {
	CapitalizationTitleName string `json:"capitalizationTitleName"`
	PlanID                  string `json:"planId"`
	TitleID                 string `json:"titleId"`
	SeriesID                string `json:"seriesId"`
	TermEndDate             string `json:"termEndDate"`
	WithdrawalReason        string `json:"withdrawalReason"`
	WithdrawalReasonOthers  string `json:"withdrawalReasonOthers,omitempty"`
	WithdrawalTotalAmount   string `json:"withdrawalTotalAmount"`
}

type QuoteCapitalizationTitleRaffle struct {
	ContactType string `json:"contactType"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
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

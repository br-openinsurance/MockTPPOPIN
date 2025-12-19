package tpp

import (
	"testing"
	"time"
)

func TestAuthServer_ResourceBaseURL(t *testing.T) {
	tests := []struct {
		name        string
		authServer  AuthServer
		apiType     APIType
		apiVersion  string
		wantURL     string
		wantErr     bool
		errContains string
	}{
		{
			name: "successful match with open-insurance path",
			authServer: AuthServer{
				Resources: []struct {
					APIType            APIType `json:"ApiFamilyType"`
					Version            string  `json:"ApiVersion"`
					Status             string  `json:"Status"`
					DiscoveryEndpoints []struct {
						Endpoint string `json:"ApiEndpoint"`
					} `json:"ApiDiscoveryEndpoints"`
				}{
					{
						APIType: APITypeHousing,
						Version: "1.0.0",
						DiscoveryEndpoints: []struct {
							Endpoint string `json:"ApiEndpoint"`
						}{
							{Endpoint: "https://api.example.com/open-insurance/housing/v1"},
						},
					},
				},
			},
			apiType:    APITypeHousing,
			apiVersion: "1.0",
			wantURL:    "https://api.example.com",
			wantErr:    false,
		},
		{
			name: "successful match with version prefix",
			authServer: AuthServer{
				Resources: []struct {
					APIType            APIType `json:"ApiFamilyType"`
					Version            string  `json:"ApiVersion"`
					Status             string  `json:"Status"`
					DiscoveryEndpoints []struct {
						Endpoint string `json:"ApiEndpoint"`
					} `json:"ApiDiscoveryEndpoints"`
				}{
					{
						APIType: APITypeCustomersPersonal,
						Version: "2.1.5",
						DiscoveryEndpoints: []struct {
							Endpoint string `json:"ApiEndpoint"`
						}{
							{Endpoint: "https://bank.example.com/open-insurance/customers-personal/v2"},
						},
					},
				},
			},
			apiType:    APITypeCustomersPersonal,
			apiVersion: "2.1",
			wantURL:    "https://bank.example.com",
			wantErr:    false,
		},
		{
			name: "successful match with prefix in path",
			authServer: AuthServer{
				Resources: []struct {
					APIType            APIType `json:"ApiFamilyType"`
					Version            string  `json:"ApiVersion"`
					Status             string  `json:"Status"`
					DiscoveryEndpoints []struct {
						Endpoint string `json:"ApiEndpoint"`
					} `json:"ApiDiscoveryEndpoints"`
				}{
					{
						APIType: APITypeAuto,
						Version: "1.0",
						DiscoveryEndpoints: []struct {
							Endpoint string `json:"ApiEndpoint"`
						}{
							{Endpoint: "https://insurer.example.com/test/open-insurance/customers-personal/v2"},
						},
					},
				},
			},
			apiType:    APITypeAuto,
			apiVersion: "1.0",
			wantURL:    "https://insurer.example.com/test",
			wantErr:    false,
		},
		{
			name: "resource not found - wrong api type",
			authServer: AuthServer{
				Resources: []struct {
					APIType            APIType `json:"ApiFamilyType"`
					Version            string  `json:"ApiVersion"`
					Status             string  `json:"Status"`
					DiscoveryEndpoints []struct {
						Endpoint string `json:"ApiEndpoint"`
					} `json:"ApiDiscoveryEndpoints"`
				}{
					{
						APIType: APITypeHousing,
						Version: "1.0",
						DiscoveryEndpoints: []struct {
							Endpoint string `json:"ApiEndpoint"`
						}{
							{Endpoint: "https://api.example.com/open-insurance/housing/v1"},
						},
					},
				},
			},
			apiType:     APITypeAuto,
			apiVersion:  "1.0",
			wantErr:     true,
			errContains: "resource not found",
		},
		{
			name: "resource not found - wrong version",
			authServer: AuthServer{
				Resources: []struct {
					APIType            APIType `json:"ApiFamilyType"`
					Version            string  `json:"ApiVersion"`
					Status             string  `json:"Status"`
					DiscoveryEndpoints []struct {
						Endpoint string `json:"ApiEndpoint"`
					} `json:"ApiDiscoveryEndpoints"`
				}{
					{
						APIType: APITypeHousing,
						Version: "1.0",
						DiscoveryEndpoints: []struct {
							Endpoint string `json:"ApiEndpoint"`
						}{
							{Endpoint: "https://api.example.com/open-insurance/housing/v1"},
						},
					},
				},
			},
			apiType:     APITypeHousing,
			apiVersion:  "2.0",
			wantErr:     true,
			errContains: "resource not found",
		},
		{
			name: "resource not found - empty resources",
			authServer: AuthServer{
				Resources: []struct {
					APIType            APIType `json:"ApiFamilyType"`
					Version            string  `json:"ApiVersion"`
					Status             string  `json:"Status"`
					DiscoveryEndpoints []struct {
						Endpoint string `json:"ApiEndpoint"`
					} `json:"ApiDiscoveryEndpoints"`
				}{},
			},
			apiType:     APITypeHousing,
			apiVersion:  "1.0",
			wantErr:     true,
			errContains: "resource not found",
		},
		{
			name: "multiple resources - finds correct one",
			authServer: AuthServer{
				Resources: []struct {
					APIType            APIType `json:"ApiFamilyType"`
					Version            string  `json:"ApiVersion"`
					Status             string  `json:"Status"`
					DiscoveryEndpoints []struct {
						Endpoint string `json:"ApiEndpoint"`
					} `json:"ApiDiscoveryEndpoints"`
				}{
					{
						APIType: APITypeHousing,
						Version: "1.0",
						DiscoveryEndpoints: []struct {
							Endpoint string `json:"ApiEndpoint"`
						}{
							{Endpoint: "https://api.example.com/open-insurance/housing/v1"},
						},
					},
					{
						APIType: APITypeAuto,
						Version: "1.0",
						DiscoveryEndpoints: []struct {
							Endpoint string `json:"ApiEndpoint"`
						}{
							{Endpoint: "https://api.example.com/open-insurance/auto/v1"},
						},
					},
				},
			},
			apiType:    APITypeAuto,
			apiVersion: "1.0",
			wantURL:    "https://api.example.com",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, err := tt.authServer.ResourceBaseURL(tt.apiType, tt.apiVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResourceBaseURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if err == nil {
					t.Errorf("ResourceBaseURL() expected error but got nil")
					return
				}
				if tt.errContains != "" && err.Error() != tt.errContains {
					t.Errorf("ResourceBaseURL() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if gotURL != tt.wantURL {
					t.Errorf("ResourceBaseURL() = %v, want %v", gotURL, tt.wantURL)
				}
			}
		})
	}
}

func TestAPIType_String(t *testing.T) {
	tests := []struct {
		name     string
		apiType  APIType
		expected string
	}{
		{"resources", APITypeResources, "resources"},
		{"customers-personal", APITypeCustomersPersonal, "customers-personal"},
		{"quote-auto", APITypeQuoteAuto, "quote-auto"},
		{"unknown", APIType("unknown-type"), "unknown-type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.apiType.String(); got != tt.expected {
				t.Errorf("APIType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAPIType_Scope(t *testing.T) {
	tests := []struct {
		name     string
		apiType  APIType
		expected string
	}{
		// Phase 2 - Data Sharing
		{"resources", APITypeResources, "resources"},
		{"customers-personal", APITypeCustomersPersonal, "customers"},
		{"customers-business", APITypeCustomersBusiness, "customers"},
		{"auto", APITypeAuto, "insurance-auto"},
		{"housing", APITypeHousing, "insurance-housing"},
		{"patrimonial", APITypePatrimonial, "insurance-patrimonial"},
		{"person", APITypePerson, "insurance-person"},
		{"acceptance-and-branches-abroad", APITypeAcceptanceAndBranchesAbroad, "insurance-acceptance-and-branches-abroad"},
		{"capitalization-title", APITypeCapitalizationTitle, "capitalization-title"},
		{"financial-assistance", APITypeFinancialAssistance, "insurance-financial-assistance"},
		{"financial-risk", APITypeFinancialRisk, "insurance-financial-risk"},
		{"life-pension", APITypeLifePension, "insurance-life-pension"},
		{"pension-plan", APITypePensionPlan, "insurance-pension-plan"},
		{"transport", APITypeTransport, "insurance-transport"},
		{"rural", APITypeRural, "insurance-rural"},
		{"responsibility", APITypeResponsibility, "insurance-responsibility"},

		// Phase 3 - Quotes
		{"quote-auto", APITypeQuoteAuto, "quote-auto quote-auto-lead"},
		{"quote-acceptance-and-branches-abroad", APITypeQuoteAcceptanceAndBranchesAbroad, "quote-acceptance-and-branches-abroad-lead"},
		{"quote-patrimonial-business", APITypeQuotePatrimonialBusiness, "quote-patrimonial-business quote-patrimonial-lead"},
		{"quote-patrimonial-condominium", APITypeQuotePatrimonialCondominium, "quote-patrimonial-condominium quote-patrimonial-lead"},
		{"quote-patrimonial-home", APITypeQuotePatrimonialHome, "quote-patrimonial-home quote-patrimonial-lead"},
		{"quote-patrimonial-diverse-risks", APITypeQuotePatrimonialDiverseRisks, "quote-patrimonial-diverse-risks quote-patrimonial-lead"},
		{"quote-housing", APITypeQuoteHousing, "quote-housing-lead"},
		{"quote-financial-risk", APITypeQuoteFinancialRisk, "quote-financial-risk-lead"},
		{"quote-responsibility", APITypeQuoteResponsibility, "quote-responsibility-lead"},
		{"quote-rural", APITypeQuoteRural, "quote-rural-lead"},
		{"quote-transport", APITypeQuoteTransport, "quote-transport-lead"},
		{"quote-person-life", APITypeQuotePersonLife, "quote-person-life quote-person-lead"},
		{"quote-person-travel", APITypeQuotePersonTravel, "quote-person-travel quote-person-lead"},
		{"quote-capitalization-title", APITypeQuoteCapitalizationTitle, "quote-capitalization-title quote-capitalization-title-lead quote-capitalization-title-raffle"},
		{"quote-capitalization-title-raffle", APITypeQuoteCapitalizationTitleRaffle, "quote-capitalization-title-raffle"},
		{"contract-life-pension", APITypeContractLifePension, "contract-life-pension contract-life-pension-lead"},
		{"dynamic-fields", APITypeDynamicFields, "dynamic-fields"},
		{"endorsement", APITypeEndorsement, "endorsement"},
		{"claim-notification-damages", APITypeClaimNotificationDamages, "claim-notification"},
		{"claim-notification-person", APITypeClaimNotificationPerson, "claim-notification"},
		{"withdrawal-capitalization-title", APITypeWithdrawalCapitalizationTitle, "withdrawal-capitalization-title"},
		{"withdrawal-pension", APITypeWithdrawalPension, "withdrawal-pension withdrawal-pension-lead"},

		// Edge cases
		{"unknown type", APIType("unknown"), ""},
		{"empty type", APIType(""), ""},
		{"consents (not in switch)", APITypeConsents, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.apiType.Scope(); got != tt.expected {
				t.Errorf("APIType.Scope() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSession_IsExpired(t *testing.T) {
	// Use a fixed time point to avoid timing issues
	baseTime := int(time.Now().Unix())

	tests := []struct {
		name     string
		session  Session
		expected bool
	}{
		{
			name: "not expired - future expiration",
			session: Session{
				ExpiresAt: baseTime + 3600, // 1 hour in the future
			},
			expected: false,
		},
		{
			name: "expired - past expiration",
			session: Session{
				ExpiresAt: baseTime - 3600, // 1 hour in the past
			},
			expected: true,
		},
		{
			name: "expired - one second in past",
			session: Session{
				ExpiresAt: baseTime - 1, // 1 second in the past
			},
			expected: true,
		},
		{
			name: "expired - zero value",
			session: Session{
				ExpiresAt: 0,
			},
			expected: true,
		},
		{
			name: "not expired - one second in future",
			session: Session{
				ExpiresAt: baseTime + 1,
			},
			expected: false,
		},
		{
			name: "not expired - far future",
			session: Session{
				ExpiresAt: baseTime + 86400, // 24 hours in the future
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This test may have a small timing window where the actual
			// timestampNow() might differ from baseTime by 1 second, but the
			// test cases use large enough deltas to avoid flakiness
			if got := tt.session.IsExpired(); got != tt.expected {
				t.Errorf("Session.IsExpired() = %v, want %v (ExpiresAt: %d)", got, tt.expected, tt.session.ExpiresAt)
			}
		})
	}
}

func TestLog_TableName(t *testing.T) {
	log := &Log{}
	expected := "logs"
	if got := log.TableName(); got != expected {
		t.Errorf("Log.TableName() = %v, want %v", got, expected)
	}
}

func TestLogs_TableName(t *testing.T) {
	logs := &Logs{}
	expected := "logs"
	if got := logs.TableName(); got != expected {
		t.Errorf("Logs.TableName() = %v, want %v", got, expected)
	}
}

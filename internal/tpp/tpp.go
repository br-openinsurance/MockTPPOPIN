package tpp

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

type Config struct {
	OrgID                         string
	SoftwareID                    string
	ParticipantsURL               string
	ParticipantRedirectURI        string
	DirectoryIssuer               string
	DirectorySoftwareStatementURL string
	DirectoryRedirectURI          string
	DirectoryEndSessionURI        string
	KeystoreURL                   string
	JWTSignerID                   string
	JWTSigner                     crypto.Signer
	ParticipantsMTLSClient        *http.Client
	DirectoryMTLSClient           *http.Client
}

type TPP struct {
	storage Storage

	orgID                  string
	softwareID             string
	participantRedirectURI string
	directoryIssuer        string
	directoryRedirectURI   string
	directoryEndSessionURI string
	jwtSignerID            string
	jwtSigner              crypto.Signer

	participantMTLSClient     *http.Client
	participantsURL           string
	participantsCacheMu       sync.Mutex
	participantsCache         []Participant
	participantsLastFetchedAt time.Time

	directoryMTLSClient                *http.Client
	directoryOpenidConfigMu            sync.Mutex
	directoryOpenidConfigCache         *OpenIDConfiguration
	directoryOpenidConfigLastFetchedAt time.Time
	directoryJWKSMu                    sync.Mutex
	directoryJWKSCache                 *jose.JSONWebKeySet
	directoryJWKSLastFetchedAt         time.Time
	directorySoftwareStatementURL      string
	keystoreURL                        string
}

func New(db *dynamodb.Client, cfg Config) *TPP {
	return &TPP{
		storage:                       storage{db: db},
		orgID:                         cfg.OrgID,
		softwareID:                    cfg.SoftwareID,
		participantsURL:               cfg.ParticipantsURL,
		participantRedirectURI:        cfg.ParticipantRedirectURI,
		jwtSignerID:                   cfg.JWTSignerID,
		jwtSigner:                     cfg.JWTSigner,
		participantMTLSClient:         cfg.ParticipantsMTLSClient,
		directoryMTLSClient:           cfg.DirectoryMTLSClient,
		directoryIssuer:               cfg.DirectoryIssuer,
		directoryRedirectURI:          cfg.DirectoryRedirectURI,
		directoryEndSessionURI:        cfg.DirectoryEndSessionURI,
		directorySoftwareStatementURL: cfg.DirectorySoftwareStatementURL,
		keystoreURL:                   cfg.KeystoreURL,
	}
}

func (t *TPP) InitFlow(ctx context.Context, flow *Flow) error {
	client, err := t.client(ctx, flow.AuthServerID)
	if err != nil {
		return err
	}

	flow.ID = uuid.NewString()
	flow.ClientID = client.ClientID
	if err := t.saveFlow(ctx, flow); err != nil {
		return err
	}

	t.Info(ctx, flow.ID, "flow initialized", slog.String("flow_id", flow.ID), slog.String("client_id", flow.ClientID), slog.String("auth_server_id", flow.AuthServerID),
		slog.String("org_id", flow.OrgID), slog.String("api_type", flow.APIType.String()), slog.String("api_version", flow.APIVersion))

	return nil
}

func (t *TPP) InitFlowAuth(ctx context.Context, flow *Flow, consent Consent) (authURL string, err error) {
	authServer, err := t.AuthServer(ctx, flow.AuthServerID, flow.OrgID)
	if err != nil {
		return "", err
	}

	consentID, err := t.createConsent(ctx, consent, flow, authServer)
	if err != nil {
		return "", err
	}
	flow.ConsentID = consentID

	authURL, codeVerifier, err := t.participantAuthURL(ctx, flow, consentID)
	if err != nil {
		return "", err
	}

	flow.CodeVerifier = codeVerifier
	if err := t.saveFlow(ctx, flow); err != nil {
		return "", err
	}

	return authURL, nil
}

// UnauthorizedFlow returns a flow that has not been authorized yet.
// It parses the response without verifying the signature to get the flow ID.
func (t *TPP) UnauthorizedFlow(ctx context.Context, response string) (*Flow, error) {
	jws, err := jwt.ParseSigned(response, []jose.SignatureAlgorithm{jose.PS256})
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var claims map[string]any
	if err := jws.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	flowID := claims["state"]
	if flowID == nil {
		return nil, errors.New("state is missing in the response")
	}

	flow, err := t.Flow(ctx, flowID.(string))
	if err != nil {
		return nil, fmt.Errorf("failed to find flow with id %s: %w", flowID, err)
	}
	t.Info(ctx, flow.ID, "received authorization response", slog.Any("response", response), slog.Any("unverified_claims", claims))

	return flow, nil
}

func (t *TPP) AuthorizeFlow(ctx context.Context, flow *Flow, response string) error {
	authServer, err := t.AuthServer(ctx, flow.AuthServerID, flow.OrgID)
	if err != nil {
		return fmt.Errorf("failed to fetch auth server: %w", err)
	}

	jwks, err := t.participantJWKS(ctx, authServer)
	if err != nil {
		return fmt.Errorf("failed to fetch participant jwks: %w", err)
	}

	parsedJWT, err := jwt.ParseSigned(response, []jose.SignatureAlgorithm{jose.PS256})
	if err != nil {
		return fmt.Errorf("failed to parse the response object: %w", err)
	}

	var jwtClaims jwt.Claims
	var claims map[string]any
	if err := parsedJWT.Claims(jwks, &jwtClaims, &claims); err != nil {
		return fmt.Errorf("failed to parse the response object: %w", err)
	}

	config, err := t.participantOpenIDConfig(ctx, authServer.OpenIDConfigURL)
	if err != nil {
		return fmt.Errorf("failed to fetch participant openid config: %w", err)
	}

	if err := jwtClaims.Validate(jwt.Expected{
		Issuer:      config.Issuer,
		AnyAudience: []string{flow.ClientID},
	}); err != nil {
		return fmt.Errorf("invalid response object jwt claims: %w", err)
	}

	code := claims["code"]
	if code == nil {
		return errors.New("authorization code is missing in the response object")
	}

	tokenResponse, err := t.participantAuthCodeToken(ctx, flow, authServer, code.(string))
	if err != nil {
		return fmt.Errorf("failed to fetch token response: %w", err)
	}

	flow.AuthCodeToken = tokenResponse.Token
	return t.saveFlow(ctx, flow)
}

func (t *TPP) PollAPIData(ctx context.Context, flow *Flow, requestUri string) (map[string]any, error) {
	t.Info(ctx, flow.ID, "creating request for "+flow.APIType.String()+" data")
	authServer, err := t.AuthServer(ctx, flow.AuthServerID, flow.OrgID)
	if err != nil {
		return nil, err
	}

	baseURL, err := authServer.ResourceBaseURL(flow.APIType, flow.APIVersion)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+requestUri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", flow.AuthCodeToken))
	req.Header.Set("X-Fapi-Interaction-Id", flow.ID)

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	t.Info(ctx, flow.ID, "received response from "+flow.APIType.String()+" data", slog.String("status", resp.Status))

	if resp.StatusCode >= 500 {
		body, _ := io.ReadAll(resp.Body)
		t.Info(ctx, flow.ID, "received error response from "+flow.APIType.String()+" data", slog.String("status", resp.Status), slog.String("body", string(body)))
		return nil, fmt.Errorf("failed to get %s data: %d", flow.APIType.String(), resp.StatusCode)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

func (t *TPP) Resources(ctx context.Context, flow *Flow, pageSize string, page string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/resources/v"+string(flow.APIVersion[0])+"/resources?page-size="+pageSize+"&page="+page)
}

func (t *TPP) CustomersPersonalIdentifications(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/customers/v"+string(flow.APIVersion[0])+"/personal/identifications")
}

func (t *TPP) CustomersPersonalAdditionalInfo(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/customers/v"+string(flow.APIVersion[0])+"/personal/complimentary-information")
}

func (t *TPP) CustomersPersonalQualifications(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/customers/v"+string(flow.APIVersion[0])+"/personal/qualifications")
}

func (t *TPP) CustomersBusinessIdentifications(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/customers/v"+string(flow.APIVersion[0])+"/business/identifications")
}

func (t *TPP) CustomersBusinessAdditionalInfo(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/customers/v"+string(flow.APIVersion[0])+"/business/complimentary-information")
}

func (t *TPP) CustomersBusinessQualifications(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/customers/v"+string(flow.APIVersion[0])+"/business/qualifications")
}

func (t *TPP) AutoPolicies(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-auto/v"+string(flow.APIVersion[0])+"/insurance-auto")
}

func (t *TPP) AutoPolicyInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-auto/v"+string(flow.APIVersion[0])+"/insurance-auto/"+dataID+"/policy-info")
}

func (t *TPP) AutoPolicyPremium(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-auto/v"+string(flow.APIVersion[0])+"/insurance-auto/"+dataID+"/premium")
}

func (t *TPP) AutoPolicyClaims(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-auto/v"+string(flow.APIVersion[0])+"/insurance-auto/"+dataID+"/claim")
}

func (t *TPP) FinancialAssistanceContracts(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-financial-assistance/v"+string(flow.APIVersion[0])+"/insurance-financial-assistance/contracts")
}

func (t *TPP) FinancialAssistanceContractInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-financial-assistance/v"+string(flow.APIVersion[0])+"/insurance-financial-assistance/"+dataID+"/contract-info")
}

func (t *TPP) FinancialAssistanceContractMovements(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-financial-assistance/v"+string(flow.APIVersion[0])+"/insurance-financial-assistance/"+dataID+"/movements")
}

func (t *TPP) HousingPolicies(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-housing/v"+string(flow.APIVersion[0])+"/insurance-housing")
}

func (t *TPP) HousingPolicyInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-housing/v"+string(flow.APIVersion[0])+"/insurance-housing/"+dataID+"/policy-info")
}

func (t *TPP) HousingPolicyPremium(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-housing/v"+string(flow.APIVersion[0])+"/insurance-housing/"+dataID+"/premium")
}

func (t *TPP) HousingPolicyClaims(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-housing/v"+string(flow.APIVersion[0])+"/insurance-housing/"+dataID+"/claim")
}

func (t *TPP) PatrimonialPolicies(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-patrimonial/v"+string(flow.APIVersion[0])+"/insurance-patrimonial")
}

func (t *TPP) PatrimonialPolicyInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-patrimonial/v"+string(flow.APIVersion[0])+"/insurance-patrimonial/"+dataID+"/policy-info")
}

func (t *TPP) PatrimonialPolicyPremium(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-patrimonial/v"+string(flow.APIVersion[0])+"/insurance-patrimonial/"+dataID+"/premium")
}

func (t *TPP) PatrimonialPolicyClaims(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-patrimonial/v"+string(flow.APIVersion[0])+"/insurance-patrimonial/"+dataID+"/claim")
}

func (t *TPP) PersonPolicies(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-person/v"+string(flow.APIVersion[0])+"/insurance-person")
}

func (t *TPP) PersonPolicyInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-person/v"+string(flow.APIVersion[0])+"/insurance-person/"+dataID+"/policy-info")
}

func (t *TPP) PersonPolicyPremium(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-person/v"+string(flow.APIVersion[0])+"/insurance-person/"+dataID+"/premium")
}

func (t *TPP) PersonPolicyClaims(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-person/v"+string(flow.APIVersion[0])+"/insurance-person/"+dataID+"/claim")
}

func (t *TPP) AcceptanceAndBranchesAbroadPolicies(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-acceptance-and-branches-abroad/v"+string(flow.APIVersion[0])+"/insurance-acceptance-and-branches-abroad")
}

func (t *TPP) AcceptanceAndBranchesAbroadPolicyInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-acceptance-and-branches-abroad/v"+string(flow.APIVersion[0])+"/insurance-acceptance-and-branches-abroad/"+dataID+"/policy-info")
}

func (t *TPP) AcceptanceAndBranchesAbroadPolicyPremium(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-acceptance-and-branches-abroad/v"+string(flow.APIVersion[0])+"/insurance-acceptance-and-branches-abroad/"+dataID+"/premium")
}

func (t *TPP) AcceptanceAndBranchesAbroadPolicyClaims(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-acceptance-and-branches-abroad/v"+string(flow.APIVersion[0])+"/insurance-acceptance-and-branches-abroad/"+dataID+"/claim")
}

func (t *TPP) ResponsibilityPolicies(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-responsibility/v"+string(flow.APIVersion[0])+"/insurance-responsibility")
}

func (t *TPP) ResponsibilityPolicyInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-responsibility/v"+string(flow.APIVersion[0])+"/insurance-responsibility/"+dataID+"/policy-info")
}

func (t *TPP) ResponsibilityPolicyPremium(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-responsibility/v"+string(flow.APIVersion[0])+"/insurance-responsibility/"+dataID+"/premium")
}

func (t *TPP) ResponsibilityPolicyClaims(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-responsibility/v"+string(flow.APIVersion[0])+"/insurance-responsibility/"+dataID+"/claim")
}

func (t *TPP) RuralPolicies(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-rural/v"+string(flow.APIVersion[0])+"/insurance-rural")
}

func (t *TPP) RuralPolicyInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-rural/v"+string(flow.APIVersion[0])+"/insurance-rural/"+dataID+"/policy-info")
}

func (t *TPP) RuralPolicyPremium(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-rural/v"+string(flow.APIVersion[0])+"/insurance-rural/"+dataID+"/premium")
}

func (t *TPP) RuralPolicyClaims(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-rural/v"+string(flow.APIVersion[0])+"/insurance-rural/"+dataID+"/claim")
}

func (t *TPP) TransportPolicies(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-transport/v"+string(flow.APIVersion[0])+"/insurance-transport")
}

func (t *TPP) TransportPolicyInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-transport/v"+string(flow.APIVersion[0])+"/insurance-transport/"+dataID+"/policy-info")
}

func (t *TPP) TransportPolicyPremium(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-transport/v"+string(flow.APIVersion[0])+"/insurance-transport/"+dataID+"/premium")
}

func (t *TPP) TransportPolicyClaims(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-transport/v"+string(flow.APIVersion[0])+"/insurance-transport/"+dataID+"/claim")
}

func (t *TPP) FinancialRiskPolicies(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-financial-risk/v"+string(flow.APIVersion[0])+"/insurance-financial-risk")
}

func (t *TPP) FinancialRiskPolicyInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-financial-risk/v"+string(flow.APIVersion[0])+"/insurance-financial-risk/"+dataID+"/policy-info")
}

func (t *TPP) FinancialRiskPolicyPremium(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-financial-risk/v"+string(flow.APIVersion[0])+"/insurance-financial-risk/"+dataID+"/premium")
}

func (t *TPP) FinancialRiskPolicyClaims(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-financial-risk/v"+string(flow.APIVersion[0])+"/insurance-financial-risk/"+dataID+"/claim")
}

func (t *TPP) CapitalizationTitlePlans(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-capitalization-title/v"+string(flow.APIVersion[0])+"/insurance-capitalization-title/plans")
}

func (t *TPP) CapitalizationTitlePlanInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-capitalization-title/v"+string(flow.APIVersion[0])+"/insurance-capitalization-title/"+dataID+"/plan-info")
}

func (t *TPP) CapitalizationTitlePlanEvents(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-capitalization-title/v"+string(flow.APIVersion[0])+"/insurance-capitalization-title/"+dataID+"/events")
}

func (t *TPP) CapitalizationTitlePlanSettlements(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-capitalization-title/v"+string(flow.APIVersion[0])+"/insurance-capitalization-title/"+dataID+"/settlements")
}

func (t *TPP) LifePensionContracts(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-life-pension/v"+string(flow.APIVersion[0])+"/insurance-life-pension/contracts")
}

func (t *TPP) LifePensionContractInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-life-pension/v"+string(flow.APIVersion[0])+"/insurance-life-pension/"+dataID+"/contract-info")
}

func (t *TPP) LifePensionContractMovements(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-life-pension/v"+string(flow.APIVersion[0])+"/insurance-life-pension/"+dataID+"/movements")
}

func (t *TPP) LifePensionContractPortabilities(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-life-pension/v"+string(flow.APIVersion[0])+"/insurance-life-pension/"+dataID+"/portabilities")
}

func (t *TPP) LifePensionContractWithdrawals(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-life-pension/v"+string(flow.APIVersion[0])+"/insurance-life-pension/"+dataID+"/withdrawals")
}

func (t *TPP) LifePensionContractClaim(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-life-pension/v"+string(flow.APIVersion[0])+"/insurance-life-pension/"+dataID+"/claim")
}

func (t *TPP) PensionPlanContracts(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-pension-plan/v"+string(flow.APIVersion[0])+"/insurance-pension-plan/contracts")
}

func (t *TPP) PensionPlanContractInfo(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-pension-plan/v"+string(flow.APIVersion[0])+"/insurance-pension-plan/"+dataID+"/contract-info")
}

func (t *TPP) PensionPlanContractMovements(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-pension-plan/v"+string(flow.APIVersion[0])+"/insurance-pension-plan/"+dataID+"/movements")
}

func (t *TPP) PensionPlanContractPortabilities(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-pension-plan/v"+string(flow.APIVersion[0])+"/insurance-pension-plan/"+dataID+"/portabilities")
}

func (t *TPP) PensionPlanContractWithdrawals(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-pension-plan/v"+string(flow.APIVersion[0])+"/insurance-pension-plan/"+dataID+"/withdrawals")
}

func (t *TPP) PensionPlanContractClaim(ctx context.Context, flow *Flow, dataID string) (map[string]any, error) {
	return t.PollAPIData(ctx, flow, "/open-insurance/insurance-pension-plan/v"+string(flow.APIVersion[0])+"/insurance-pension-plan/"+dataID+"/claim")
}

func (t *TPP) createConsent(ctx context.Context, consent Consent, flow *Flow, authServer AuthServer) (consentID string, err error) {
	accessToken, err := t.participantClientCredentialsToken(ctx, flow, authServer, "consents")
	if err != nil {
		return "", err
	}

	data := map[string]any{
		"loggedUser": map[string]any{
			"document": map[string]any{
				"identification": consent.UserCPF,
				"rel":            "CPF",
			},
		},
		"expirationDateTime": formatDateTime(timeNow().Add(1 * time.Hour)),
		"permissions":        consent.Permissions,
	}
	if consent.BusinessCNPJ != "" {
		data["businessEntity"] = map[string]any{
			"document": map[string]any{
				"identification": consent.BusinessCNPJ,
				"rel":            "CNPJ",
			},
		}
	}
	if consent.Endorsement != nil {
		data["endorsementInformation"] = consent.Endorsement
	}
	if consent.ClaimNotification != nil {
		data["claimNotificationInformation"] = consent.ClaimNotification
	}
	if consent.WithdrawalLifePension != nil {
		withdrawal := map[string]any{
			"certificateId":    consent.WithdrawalLifePension.CertificateID,
			"productName":      consent.WithdrawalLifePension.ProductName,
			"withdrawalType":   consent.WithdrawalLifePension.WithdrawalType,
			"withdrawalReason": consent.WithdrawalLifePension.WithdrawalReason,
		}
		if consent.WithdrawalLifePension.WithdrawalReasonOthers != "" {
			withdrawal["withdrawalReasonOthers"] = consent.WithdrawalLifePension.WithdrawalReasonOthers
		}
		if consent.WithdrawalLifePension.DesiredTotalAmount != "" {
			withdrawal["desiredTotalAmount"] = map[string]any{
				"amount": consent.WithdrawalLifePension.DesiredTotalAmount,
				"unit": map[string]any{
					"code":        "R$",
					"description": "BRL",
				},
			}
		}
		if consent.WithdrawalLifePension.PmbacAmount != "" {
			withdrawal["pmbacAmount"] = map[string]any{
				"amount": consent.WithdrawalLifePension.PmbacAmount,
				"unit": map[string]any{
					"code":        "R$",
					"description": "BRL",
				},
			}
		}
		data["withdrawalLifePensionInformation"] = withdrawal
	}
	if consent.WithdrawalCapitalizationTitle != nil {
		withdrawal := map[string]any{
			"capitalizationTitleName": consent.WithdrawalCapitalizationTitle.CapitalizationTitleName,
			"planId":                  consent.WithdrawalCapitalizationTitle.PlanID,
			"titleId":                 consent.WithdrawalCapitalizationTitle.TitleID,
			"seriesId":                consent.WithdrawalCapitalizationTitle.SeriesID,
			"termEndDate":             consent.WithdrawalCapitalizationTitle.TermEndDate,
			"withdrawalReason":        consent.WithdrawalCapitalizationTitle.WithdrawalReason,
		}
		if consent.WithdrawalCapitalizationTitle.WithdrawalReasonOthers != "" {
			withdrawal["withdrawalReasonOthers"] = consent.WithdrawalCapitalizationTitle.WithdrawalReasonOthers
		}
		if consent.WithdrawalCapitalizationTitle.WithdrawalTotalAmount != "" {
			withdrawal["withdrawalTotalAmount"] = map[string]any{
				"amount": consent.WithdrawalCapitalizationTitle.WithdrawalTotalAmount,
				"unit": map[string]any{
					"code":        "R$",
					"description": "BRL",
				},
			}
		}
		data["withdrawalCapitalizationInformation"] = withdrawal
	}
	if consent.QuoteCapitalizationTitleRaffle != nil {
		raffle := map[string]any{
			"contactType": consent.QuoteCapitalizationTitleRaffle.ContactType,
		}
		if consent.QuoteCapitalizationTitleRaffle.Email != "" {
			raffle["email"] = consent.QuoteCapitalizationTitleRaffle.Email
		}
		if consent.QuoteCapitalizationTitleRaffle.Phone != "" {
			raffle["phone"] = consent.QuoteCapitalizationTitleRaffle.Phone
		}
		data["raffleCapitalizationTitleInformation"] = raffle
	}
	t.Info(ctx, flow.ID, "creating consent", slog.Any("consent_data", data))

	payload, err := json.Marshal(map[string]any{
		"data": data,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	baseURL, err := authServer.ResourceBaseURL(APITypeConsents, "2")
	if err != nil {
		return "", fmt.Errorf("failed to get resource host for consents: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/open-insurance/consents/v2/consents", bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create consent request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fapi-Interaction-Id", flow.ID)
	req.Header.Set("X-Idempotency-Key", uuid.NewString())

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Error(ctx, flow.ID, "failed to create consent", slog.String("status", resp.Status), slog.String("body", string(body)))
		return "", fmt.Errorf("failed to create consent: %s", resp.Status)
	}

	var result struct {
		Data struct {
			ID string `json:"consentId"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	t.Info(ctx, flow.ID, "consent successfully created", slog.String("consent_id", result.Data.ID))
	return result.Data.ID, nil
}

func (t *TPP) CreateQuoteAutoLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-auto/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) PatchQuoteAutoLead(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-auto/"+"/v"+string(flow.APIVersion[0])+"/lead/request/"+consentID, data)
}

func (t *TPP) CreateQuoteAuto(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-auto/"+"/v"+string(flow.APIVersion[0])+"/request", data)
}

func (t *TPP) QuoteAuto(ctx context.Context, flow *Flow, consentID string) (map[string]any, error) {
	return t.fetchClientCredentials(ctx, flow, "/open-insurance/quote-auto/"+"/v"+string(flow.APIVersion[0])+"/request/"+consentID+"/quote-status")
}

func (t *TPP) PatchQuoteAuto(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-auto/"+"/v"+string(flow.APIVersion[0])+"/request/"+consentID, data)
}

func (t *TPP) CreateQuoteAcceptanceAndBranchesAbroadLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-acceptance-and-branches-abroad/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) PatchQuoteAcceptanceAndBranchesAbroadLead(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-acceptance-and-branches-abroad/"+"/v"+string(flow.APIVersion[0])+"/lead/request/"+consentID, data)
}

func (t *TPP) CreateQuotePatrimonialLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) PatchQuotePatrimonialLead(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/"+"/v"+string(flow.APIVersion[0])+"/lead/request/"+consentID, data)
}

func (t *TPP) CreateQuotePatrimonialBusiness(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/business/request", data)
}

func (t *TPP) QuotePatrimonialBusiness(ctx context.Context, flow *Flow, consentID string) (map[string]any, error) {
	return t.fetchClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/business/request/"+consentID+"/quote-status")
}

func (t *TPP) PatchQuotePatrimonialBusiness(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/business/request/"+consentID, data)
}

func (t *TPP) CreateQuotePatrimonialCondominium(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/condominium/request", data)
}

func (t *TPP) QuotePatrimonialCondominium(ctx context.Context, flow *Flow, consentID string) (map[string]any, error) {
	return t.fetchClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/condominium/request/"+consentID+"/quote-status")
}

func (t *TPP) PatchQuotePatrimonialCondominium(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/condominium/request/"+consentID, data)
}

func (t *TPP) CreateQuotePatrimonialHome(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/home/request", data)
}

func (t *TPP) QuotePatrimonialHome(ctx context.Context, flow *Flow, consentID string) (map[string]any, error) {
	return t.fetchClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/home/request/"+consentID+"/quote-status")
}

func (t *TPP) PatchQuotePatrimonialHome(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/home/request/"+consentID, data)
}

func (t *TPP) CreateQuotePatrimonialDiverseRisks(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/diverse-risks/request", data)
}

func (t *TPP) QuotePatrimonialDiverseRisks(ctx context.Context, flow *Flow, consentID string) (map[string]any, error) {
	return t.fetchClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/diverse-risks/request/"+consentID+"/quote-status")
}

func (t *TPP) PatchQuotePatrimonialDiverseRisks(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-patrimonial/v"+string(flow.APIVersion[0])+"/diverse-risks/request/"+consentID, data)
}

func (t *TPP) CreateQuoteHousingLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-housing/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) PatchQuoteHousingLead(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-housing/"+"/v"+string(flow.APIVersion[0])+"/lead/request/"+consentID, data)
}

func (t *TPP) CreateQuoteFinancialRiskLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-financial-risk/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) PatchQuoteFinancialRiskLead(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-financial-risk/"+"/v"+string(flow.APIVersion[0])+"/lead/request/"+consentID, data)
}

func (t *TPP) CreateQuoteResponsibilityLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-responsibility/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) PatchQuoteResponsibilityLead(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-responsibility/"+"/v"+string(flow.APIVersion[0])+"/lead/request/"+consentID, data)
}

func (t *TPP) CreateQuoteRuralLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-rural/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) PatchQuoteRuralLead(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-rural/"+"/v"+string(flow.APIVersion[0])+"/lead/request/"+consentID, data)
}

func (t *TPP) CreateQuoteTransportLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-transport/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) PatchQuoteTransportLead(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-transport/"+"/v"+string(flow.APIVersion[0])+"/lead/request/"+consentID, data)
}

func (t *TPP) CreateQuotePersonLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-person/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) PatchQuotePersonLead(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-person/"+"/v"+string(flow.APIVersion[0])+"/lead/request/"+consentID, data)
}

func (t *TPP) CreateQuotePersonLife(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-person/v"+string(flow.APIVersion[0])+"/life/request", data)
}

func (t *TPP) QuotePersonLife(ctx context.Context, flow *Flow, consentID string) (map[string]any, error) {
	return t.fetchClientCredentials(ctx, flow, "/open-insurance/quote-person/v"+string(flow.APIVersion[0])+"/life/request/"+consentID+"/quote-status")
}

func (t *TPP) PatchQuotePersonLife(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-person/v"+string(flow.APIVersion[0])+"/life/request/"+consentID, data)
}

func (t *TPP) CreateQuotePersonTravel(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-person/v"+string(flow.APIVersion[0])+"/travel/request", data)
}

func (t *TPP) QuotePersonTravel(ctx context.Context, flow *Flow, consentID string) (map[string]any, error) {
	return t.fetchClientCredentials(ctx, flow, "/open-insurance/quote-person/v"+string(flow.APIVersion[0])+"/travel/request/"+consentID+"/quote-status")
}

func (t *TPP) PatchQuotePersonTravel(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-person/v"+string(flow.APIVersion[0])+"/travel/request/"+consentID, data)
}

func (t *TPP) CreateQuoteCapitalizationTitleLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-capitalization-title/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) PatchQuoteCapitalizationTitleLead(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-capitalization-title/"+"/v"+string(flow.APIVersion[0])+"/lead/request/"+consentID, data)
}

func (t *TPP) CreateQuoteCapitalizationTitle(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/quote-capitalization-title/v"+string(flow.APIVersion[0])+"/request", data)
}

func (t *TPP) QuoteCapitalizationTitle(ctx context.Context, flow *Flow, consentID string) (map[string]any, error) {
	return t.fetchClientCredentials(ctx, flow, "/open-insurance/quote-capitalization-title/v"+string(flow.APIVersion[0])+"/request/"+consentID+"/quote-status")
}

func (t *TPP) PatchQuoteCapitalizationTitle(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/quote-capitalization-title/v"+string(flow.APIVersion[0])+"/request/"+consentID, data)
}

func (t *TPP) CreateQuoteCapitalizationTitleRaffle(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	authServer, err := t.AuthServer(ctx, flow.AuthServerID, flow.OrgID)
	if err != nil {
		return nil, err
	}

	baseURL, err := authServer.ResourceBaseURL(APITypeQuoteCapitalizationTitle, flow.APIVersion)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/open-insurance/quote-capitalization-title/v"+string(flow.APIVersion[0])+"/raffle/request", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", flow.AuthCodeToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fapi-Interaction-Id", flow.ID)
	req.Header.Set("X-Idempotency-Key", uuid.NewString())

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create quote capitalization title raffle: %s %s", resp.Status, string(body))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	t.Info(ctx, flow.ID, "quote capitalization title raffle successfully created", slog.Any("quote_capitalization_title_raffle", result))
	return result, nil
}

func (t *TPP) CreateQuoteContractLifePensionLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/contract-life-pension/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) PatchQuoteContractLifePensionLead(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/contract-life-pension/"+"/v"+string(flow.APIVersion[0])+"/lead/request/"+consentID, data)
}

func (t *TPP) CreateQuoteContractLifePension(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClientCredentials(ctx, flow, "/open-insurance/contract-life-pension/v"+string(flow.APIVersion[0])+"/request", data)
}

func (t *TPP) QuoteContractLifePension(ctx context.Context, flow *Flow, consentID string) (map[string]any, error) {
	return t.fetchClientCredentials(ctx, flow, "/open-insurance/contract-life-pension/v"+string(flow.APIVersion[0])+"/request/"+consentID+"/quote-status")
}

func (t *TPP) PatchQuoteContractLifePension(ctx context.Context, flow *Flow, consentID string, data map[string]any) (map[string]any, error) {
	return t.patchClientCredentials(ctx, flow, "/open-insurance/contract-life-pension/v"+string(flow.APIVersion[0])+"/request/"+consentID, data)
}

func (t *TPP) DynamicFieldsDamageAndPerson(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.fetchClientCredentials(ctx, flow, "/open-insurance/dynamic-fields/v"+string(flow.APIVersion[0])+"/damage-and-person")
}

func (t *TPP) DynamicFieldsCapitalizationTitle(ctx context.Context, flow *Flow) (map[string]any, error) {
	return t.fetchClientCredentials(ctx, flow, "/open-insurance/dynamic-fields/v"+string(flow.APIVersion[0])+"/capitalization-title")
}

func (t *TPP) CreateEndorsement(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	authServer, err := t.AuthServer(ctx, flow.AuthServerID, flow.OrgID)
	if err != nil {
		return nil, err
	}

	baseURL, err := authServer.ResourceBaseURL(flow.APIType, flow.APIVersion)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/open-insurance/endorsement/v"+string(flow.APIVersion[0])+"/request"+"/"+flow.ConsentID, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", flow.AuthCodeToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fapi-Interaction-Id", flow.ID)
	req.Header.Set("X-Idempotency-Key", uuid.NewString())

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create endorsement: %s %s", resp.Status, string(body))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	t.Info(ctx, flow.ID, "endorsement successfully created", slog.Any("endorsement", result))
	return result, nil
}

func (t *TPP) CreateClaimNotificationDamages(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClaimNotification(ctx, flow, "/open-insurance/claim-notification/v"+string(flow.APIVersion[0])+"/request/damage/"+flow.ConsentID, data)
}

func (t *TPP) CreateClaimNotificationPerson(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createClaimNotification(ctx, flow, "/open-insurance/claim-notification/v"+string(flow.APIVersion[0])+"/request/person/"+flow.ConsentID, data)
}

//nolint:dupl
func (t *TPP) createClaimNotification(ctx context.Context, flow *Flow, endpoint string, data map[string]any) (map[string]any, error) {
	authServer, err := t.AuthServer(ctx, flow.AuthServerID, flow.OrgID)
	if err != nil {
		return nil, err
	}

	baseURL, err := authServer.ResourceBaseURL(flow.APIType, flow.APIVersion)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", flow.AuthCodeToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fapi-Interaction-Id", flow.ID)
	req.Header.Set("X-Idempotency-Key", uuid.NewString())

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create claim notification: %s %s", resp.Status, string(body))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	t.Info(ctx, flow.ID, "claim notification successfully created", slog.Any("claim_notification", result))
	return result, nil
}

func (t *TPP) CreateWithdrawalCapitalizationTitle(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createWithdrawal(ctx, flow, "/open-insurance/withdrawal/v"+string(flow.APIVersion[0])+"/capitalization-title/request", data)
}

func (t *TPP) CreateWithdrawalPensionLead(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createWithdrawal(ctx, flow, "/open-insurance/withdrawal/v"+string(flow.APIVersion[0])+"/lead/request", data)
}

func (t *TPP) CreateWithdrawalPension(ctx context.Context, flow *Flow, data map[string]any) (map[string]any, error) {
	return t.createWithdrawal(ctx, flow, "/open-insurance/withdrawal/v"+string(flow.APIVersion[0])+"/pension/request", data)
}

//nolint:dupl
func (t *TPP) createWithdrawal(ctx context.Context, flow *Flow, endpoint string, data map[string]any) (map[string]any, error) {
	authServer, err := t.AuthServer(ctx, flow.AuthServerID, flow.OrgID)
	if err != nil {
		return nil, err
	}

	baseURL, err := authServer.ResourceBaseURL(flow.APIType, flow.APIVersion)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", flow.AuthCodeToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fapi-Interaction-Id", flow.ID)
	req.Header.Set("X-Idempotency-Key", uuid.NewString())

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create withdrawal: %s %s", resp.Status, string(body))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	t.Info(ctx, flow.ID, "withdrawal successfully created", slog.Any("withdrawal", result))
	return result, nil
}

//nolint:dupl
func (t *TPP) createClientCredentials(ctx context.Context, flow *Flow, endpoint string, data map[string]any) (map[string]any, error) {
	authServer, err := t.AuthServer(ctx, flow.AuthServerID, flow.OrgID)
	if err != nil {
		return nil, err
	}

	accessToken, err := t.participantClientCredentialsToken(ctx, flow, authServer, flow.APIType.Scope())
	if err != nil {
		return nil, err
	}

	baseURL, err := authServer.ResourceBaseURL(flow.APIType, flow.APIVersion)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fapi-Interaction-Id", flow.ID)
	req.Header.Set("X-Idempotency-Key", uuid.NewString())

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create resource: %s %s", resp.Status, string(body))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	t.Info(ctx, flow.ID, "resource successfully created", slog.Any("resource", result))
	return result, nil
}

func (t *TPP) fetchClientCredentials(ctx context.Context, flow *Flow, endpoint string) (map[string]any, error) {
	authServer, err := t.AuthServer(ctx, flow.AuthServerID, flow.OrgID)
	if err != nil {
		return nil, err
	}

	accessToken, err := t.participantClientCredentialsToken(ctx, flow, authServer, flow.APIType.Scope())
	if err != nil {
		return nil, err
	}

	baseURL, err := authServer.ResourceBaseURL(flow.APIType, flow.APIVersion)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("X-Fapi-Interaction-Id", flow.ID)

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get resource: %s %s", resp.Status, string(body))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	t.Info(ctx, flow.ID, "resource successfully retrieved", slog.Any("resource", result))
	return result, nil
}

//nolint:dupl
func (t *TPP) patchClientCredentials(ctx context.Context, flow *Flow, endpoint string, data map[string]any) (map[string]any, error) {
	authServer, err := t.AuthServer(ctx, flow.AuthServerID, flow.OrgID)
	if err != nil {
		return nil, err
	}

	accessToken, err := t.participantClientCredentialsToken(ctx, flow, authServer, flow.APIType.Scope())
	if err != nil {
		return nil, err
	}

	baseURL, err := authServer.ResourceBaseURL(flow.APIType, flow.APIVersion)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, baseURL+endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Fapi-Interaction-Id", flow.ID)
	req.Header.Set("X-Idempotency-Key", uuid.NewString())

	resp, err := t.participantMTLSClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to patch resource: %s %s", resp.Status, string(body))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	t.Info(ctx, flow.ID, "resource successfully patched", slog.Any("resource", result))
	return result, nil
}

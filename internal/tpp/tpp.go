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

	host, err := authServer.ResourceHost(flow.APIType, flow.APIVersion)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+requestUri, nil)
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
	t.Info(ctx, flow.ID, "creating consent", slog.Any("consent_data", data))

	payload, err := json.Marshal(map[string]any{
		"data": data,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	host, err := authServer.ResourceHost(APITypeConsents, "2")
	if err != nil {
		return "", fmt.Errorf("failed to get resource host for consents: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, host+"/open-insurance/consents/v2/consents", bytes.NewBuffer(payload))
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

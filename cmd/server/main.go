package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/br-openinsurance/MockTPPOPIN/internal/api"
	"github.com/br-openinsurance/MockTPPOPIN/internal/tpp"
	"github.com/google/uuid"
)

type Environment string

const (
	LocalEnvironment Environment = "LOCAL"
)

var (
	Env             = envValue("ENV", LocalEnvironment)
	OrgID           = envValue("ORG_ID", "4b75db2e-a0c0-4359-a077-684e88fa695c")
	SoftwareID      = envValue("SOFTWARE_ID", "fec2fd24-6b2e-4c96-9786-771595a33bff")
	Host            = envValue("HOST", "https://mocktpp.local")
	ParticipantsURL = envValue("PARTICIPANTS_URL", "https://data.sandbox.directory.opinbrasil.com.br/participants")
	KeystoreURL     = envValue("KEYSTORE_URL", "https://keystore.sandbox.directory.opinbrasil.com.br")

	// DirectoryIssuer is the issuer used by the directory to sign ID tokens, etc.
	DirectoryIssuer = envValue("DIRECTORY_ISSUER", "https://directory.local")
	// DirectoryIssuer = envValue("DIRECTORY_ISSUER", "https://auth.sandbox.directory.opinbrasil.com.br")
	// DirectoryAPIHost is the host used to make API requests to the directory. (e.g. for requesting a software statement).
	DirectoryAPIHost = envValue("DIRECTORY_API_HOST", "https://matls-directory.local")
	// DirectoryAPIHost = envValue("DIRECTORY_API_HOST", "https://matls-api.sandbox.directory.opinbrasil.com.br")

	// TPPClientSignerID is the ID of the JWK used to sign JWTs when interacting with participants of the ecosystem.
	TPPClientSignerID = envValue("TPP_CLIENT_SIGNER_ID", "OnkkgaeGBBDl26sfA1JG-teYybf1aR4LsLYedxm9Yy0")
	// TPPClientSigningKeySSMParamName is the parameter used to sign JWTs for the tpp client.
	TPPClientSigningKeySSMParamName = envValue("TPP_CLIENT_SIGNING_KEY_SSM_PARAM", "/mocktpp/tpp-client-signing-key")
	// TPPClientMTLSCertSSMParamName and TPPClientMTLSKeySSMParamName are the parameters used for mutual TLS connections for the tpp client.
	TPPClientMTLSCertSSMParamName = envValue("TPP_CLIENT_MTLS_CERT_SSM_PARAM", "/mocktpp/tpp-client-transport-cert")
	TPPClientMTLSKeySSMParamName  = envValue("TPP_CLIENT_MTLS_KEY_SSM_PARAM", "/mocktpp/tpp-client-transport-key")
	TPPCACertSSMParamName         = envValue("TPP_CA_CERT_SSM_PARAM", "/mocktpp/tpp-ca-cert")

	Port = envValue("PORT", "80")
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slog.SetDefault(logger())

	slog.Info("setting up mock tpp", "env", Env)
	http.DefaultClient = httpClient()
	awsConfig, err := awsConfig(ctx)
	if err != nil {
		slog.Error("failed to load aws config", "error", err)
		os.Exit(1)
	}

	// Database.
	db := dynamodb.NewFromConfig(*awsConfig)

	// Keys.
	slog.Info("creating ssm client")
	ssmClient := ssm.NewFromConfig(*awsConfig)
	slog.Info("ssm client created")

	tppClientSigner, err := signerFromSSM(ctx, ssmClient, TPPClientSigningKeySSMParamName)
	if err != nil {
		slog.Error("could not load signer for tpp", "error", err)
		os.Exit(1)
	}

	tppClientTLSCert, err := tlsCertFromSSM(ctx, ssmClient, TPPClientMTLSCertSSMParamName, TPPClientMTLSKeySSMParamName)
	if err != nil {
		slog.Error("could not load tpp client TLS certificate", "error", err)
		os.Exit(1)
	}

	caCertPool, err := caCertPoolFromSSM(ctx, ssmClient, TPPCACertSSMParamName)
	if err != nil {
		slog.Error("could not load tpp client CA certificate", "error", err)
		os.Exit(1)
	}

	// Third Party Provider.
	tppService := tpp.New(db, tpp.Config{
		OrgID:                         OrgID,
		SoftwareID:                    SoftwareID,
		DirectoryIssuer:               DirectoryIssuer,
		DirectorySoftwareStatementURL: DirectoryAPIHost + "/organisations/" + OrgID + "/softwarestatements/" + SoftwareID + "/assertion",
		DirectoryRedirectURI:          Host + "/auth/directory/callback",
		ParticipantsURL:               ParticipantsURL,
		ParticipantRedirectURI:        Host + "/auth/callback",
		JWTSignerID:                   TPPClientSignerID,
		JWTSigner:                     tppClientSigner,
		DirectoryMTLSClient:           mtlsHTTPClient(tppClientTLSCert, caCertPool),
		ParticipantsMTLSClient:        unsecureMTLSHTTPClient(tppClientTLSCert),
		KeystoreURL:                   KeystoreURL,
	})

	// Servers.
	mux := http.NewServeMux()
	mux.Handle("/", api.Handler(Host, tppService))
	handler := middleware(mux)

	slog.Info("starting mock tpp")

	if Env == LocalEnvironment {
		//nolint:gosec
		if err := http.ListenAndServe(":"+Port, handler); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("failed to start mock tpp", "error", err)
			os.Exit(1)
		}
		return
	}

	lambdaAdapter := httpadapter.New(handler)
	lambda.Start(lambdaAdapter.Proxy)
}

func awsConfig(ctx context.Context) (*aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to load aws config, %w", err)
	}

	if Env == LocalEnvironment {
		cfg.BaseEndpoint = aws.String("http://aws.local:4566")
		cfg.Region = "us-east-1"
		cfg.Credentials = credentials.NewStaticCredentialsProvider("test", "test", "")
	}
	return &cfg, nil
}

func httpClient() *http.Client {
	tlsConfig := &tls.Config{
		MinVersion:    tls.VersionTLS12,
		Renegotiation: tls.RenegotiateOnceAsClient,
	}
	if Env == LocalEnvironment {
		tlsConfig.InsecureSkipVerify = true
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func logger() *slog.Logger {
	return slog.New(&logCtxHandler{
		Handler: slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
			// Make sure time is logged in UTC.
			ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
				if attr.Key == slog.TimeKey {
					now := time.Now().UTC()
					return slog.Attr{Key: slog.TimeKey, Value: slog.StringValue(now.String())}
				}
				return attr
			},
		})})
}

type logCtxHandler struct {
	slog.Handler
}

func (h *logCtxHandler) Handle(ctx context.Context, r slog.Record) error {
	if interactionID, ok := ctx.Value(api.InteractionIDKey).(string); ok {
		r.AddAttrs(slog.String("interaction_id", interactionID))
	}

	return h.Handler.Handle(ctx, r)
}

func tlsCertFromSSM(ctx context.Context, ssmClient *ssm.Client, certParamName, keyParamName string) (tls.Certificate, error) {
	certOut, err := ssmParam(ctx, ssmClient, certParamName)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not fetch cert from SSM (%s): %w", certParamName, err)
	}

	keyOut, err := ssmParam(ctx, ssmClient, keyParamName)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not fetch key from SSM (%s): %w", keyParamName, err)
	}

	certPEM := []byte(certOut)
	keyPEM := []byte(keyOut)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not parse TLS certificate: %w", err)
	}

	return tlsCert, nil
}

func caCertPoolFromSSM(ctx context.Context, ssmClient *ssm.Client, certParamName string) (*x509.CertPool, error) {
	certPEM, err := ssmParam(ctx, ssmClient, certParamName)
	if err != nil {
		return nil, fmt.Errorf("could not fetch CA cert from SSM (%s): %w", certParamName, err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(certPEM))
	return caCertPool, nil
}

func ssmParam(ctx context.Context, ssmClient *ssm.Client, paramName string) (string, error) {
	withDecryption := true

	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: &withDecryption,
	})
	if err != nil {
		return "", fmt.Errorf("could not fetch param from SSM (%s): %w", paramName, err)
	}

	return aws.ToString(out.Parameter.Value), nil
}

func mtlsHTTPClient(cert tls.Certificate, caCertPool *x509.CertPool) *http.Client {

	tlsConfig := &tls.Config{
		Certificates:  []tls.Certificate{cert},
		MinVersion:    tls.VersionTLS12,
		Renegotiation: tls.RenegotiateOnceAsClient,
		RootCAs:       caCertPool,
	}
	if Env == LocalEnvironment {
		tlsConfig.InsecureSkipVerify = true
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func unsecureMTLSHTTPClient(cert tls.Certificate) *http.Client {
	tlsConfig := &tls.Config{
		//nolint:gosec
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS12,
		Renegotiation:      tls.RenegotiateOnceAsClient,
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func signerFromSSM(ctx context.Context, ssmClient *ssm.Client, paramName string) (crypto.Signer, error) {
	out, err := ssmParam(ctx, ssmClient, paramName)
	if err != nil {
		return nil, fmt.Errorf("could not fetch private key from SSM: %w", err)
	}

	block, _ := pem.Decode([]byte(out))
	if block == nil || block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block")
	}

	var parsedKey any
	switch block.Type {
	case "PRIVATE KEY":
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsedKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		err = fmt.Errorf("unsupported key type: %s", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	signer, ok := parsedKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Signer")
	}

	return signer, nil
}

func middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, api.InteractionIDKey, uuid.New().String())
		slog.InfoContext(ctx, "request received", "method", r.Method, "path", r.URL.Path)

		start := time.Now().UTC()
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "error", rec, "stack", string(debug.Stack()))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			slog.InfoContext(ctx, "request completed", slog.Duration("duration", time.Since(start)))
		}()

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// envValue retrieves an environment variable or returns a fallback value if not found.
func envValue[T ~string](key, fallback T) T {
	if value, exists := os.LookupEnv(string(key)); exists {
		return T(value)
	}
	return fallback
}

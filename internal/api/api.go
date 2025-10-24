package api

import (
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"slices"

	"github.com/br-openinsurance/MockTPPOPIN/internal/tpp"
	"github.com/br-openinsurance/MockTPPOPIN/ui"
	"github.com/rs/cors"
	"github.com/unrolled/secure"
)

const (
	cookieSessionID = "session_id"
)

func Handler(host string, tppService *tpp.TPP) http.Handler {
	secureMiddleware := secure.New(secure.Options{
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' $NONCE; style-src 'self' $NONCE",
	})
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{host},
		AllowCredentials: true,
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
		},
	})

	tmpl, err := template.ParseFS(ui.Templates, "templates/*.html")
	if err != nil {
		slog.Error("could not parse templates", "error", err)
		os.Exit(1)
	}

	staticSub, err := fs.Sub(ui.StaticFiles, "static")
	if err != nil {
		slog.Error("error getting static files", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	mux.Handle("GET /", sessionMiddleware(tppService, serversHandler(tmpl, tppService)))
	mux.Handle("GET /login", loginHandler(tmpl))
	mux.Handle("GET /auth/directory", directoryAuthHandler(tmpl, tppService))
	mux.Handle("GET /auth/directory/callback", unauthorizedSessionMiddleware(tppService, directoryCallbackHandler(tmpl, tppService)))

	mux.Handle("GET /servers", sessionMiddleware(tppService, serversHandler(tmpl, tppService)))

	mux.Handle("GET /servers/{org_id}/{auth_server_id}/flows", sessionMiddleware(tppService, flowsHandler(tmpl, tppService)))
	mux.Handle("POST /servers/{org_id}/{auth_server_id}/flows", sessionMiddleware(tppService, initFlowHandler(tmpl, tppService)))
	mux.Handle("GET /flows/{flow_id}", flowMiddleware(tppService, flowHandler(tmpl)))
	mux.Handle("POST /flows/{flow_id}", flowMiddleware(tppService, flowInitAuthHandler(tmpl, tppService)))
	mux.Handle("GET /flows/{flow_id}/logs", flowMiddleware(tppService, flowLogsHandler(tppService)))
	mux.Handle("GET /auth/callback", sessionMiddleware(tppService, callbackHandler(tmpl, tppService)))
	mux.Handle("GET /flows/{flow_id}/customers-personal-identification", flowMiddleware(tppService, customersPersonalIdentificationHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/customers-personal-qualification", flowMiddleware(tppService, customersPersonalQualificationHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/customers-personal-additional-info", flowMiddleware(tppService, customersPersonalAdditionalInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/customers-business-identification", flowMiddleware(tppService, customersBusinessIdentificationHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/customers-business-qualification", flowMiddleware(tppService, customersBusinessQualificationHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/customers-business-additional-info", flowMiddleware(tppService, customersBusinessAdditionalInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-auto-policies", flowMiddleware(tppService, insuranceAutoPoliciesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-auto-policy-info/{data_id}", flowMiddleware(tppService, insuranceAutoPolicyInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-auto-policy-premium/{data_id}", flowMiddleware(tppService, insuranceAutoPolicyPremiumHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-auto-policy-claim/{data_id}", flowMiddleware(tppService, insuranceAutoPolicyClaimsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/housing", flowMiddleware(tppService, housingPoliciesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-acceptance-and-branches-abroad-policies", flowMiddleware(tppService, acceptanceAndBranchesAbroadPoliciesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-acceptance-and-branches-abroad-policy-info/{data_id}", flowMiddleware(tppService, acceptanceAndBranchesAbroadPolicyInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-acceptance-and-branches-abroad-policy-premium/{data_id}", flowMiddleware(tppService, acceptanceAndBranchesAbroadPolicyPremiumHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-acceptance-and-branches-abroad-policy-claim/{data_id}", flowMiddleware(tppService, acceptanceAndBranchesAbroadPolicyClaimsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-capitalization-title-plans", flowMiddleware(tppService, capitalizationTitlePlansHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-capitalization-title-plan-info/{data_id}", flowMiddleware(tppService, capitalizationTitlePlanInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-capitalization-title-plan-events/{data_id}", flowMiddleware(tppService, capitalizationTitlePlanEventsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-capitalization-title-plan-settlements/{data_id}", flowMiddleware(tppService, capitalizationTitlePlanSettlementsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/financial-assistance-contracts", flowMiddleware(tppService, insuranceFinancialAssistanceContractsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/financial-assistance-contract-info/{data_id}", flowMiddleware(tppService, insuranceFinancialAssistanceContractInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/financial-assistance-contract-movements/{data_id}", flowMiddleware(tppService, insuranceFinancialAssistanceContractMovementsHandler(tppService)))

	return corsMiddleware.Handler(secureMiddleware.Handler(mux))
}

func loginHandler(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "start login")

		page := struct {
			Nonce string
		}{
			Nonce: secure.CSPNonce(r.Context()),
		}
		if err := tmpl.ExecuteTemplate(w, "login.html", page); err != nil {
			slog.ErrorContext(r.Context(), "could not execute login template", "error", err)
			renderError(w, r, tmpl, err)
			return
		}
	}
}

func directoryAuthHandler(tmpl *template.Template, tppService *tpp.TPP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.InfoContext(r.Context(), "start directory auth")

		session, authURL, err := tppService.InitSession(r.Context())
		if err != nil {
			slog.ErrorContext(r.Context(), "error creating session", "error", err)
			renderError(w, r, tmpl, err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieSessionID,
			Value:    session.ID,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   60 * 60, // 1 hour.
			Path:     "/",
		})

		redirect(w, authURL)
	}
}

func directoryCallbackHandler(tmpl *template.Template, tppService *tpp.TPP) sessionHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, session *tpp.Session) {
		slog.InfoContext(r.Context(), "received directory callback")

		response := r.URL.Query().Get("response")
		if err := tppService.AuthorizeSession(r.Context(), session, response); err != nil {
			slog.ErrorContext(r.Context(), "error authorizing session", "error", err)
			renderError(w, r, tmpl, err)
			return
		}

		redirect(w, "/servers")
	}
}

func serversHandler(tmpl *template.Template, tppService *tpp.TPP) sessionHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, session *tpp.Session) {
		slog.InfoContext(r.Context(), "displaying participants")

		participants, err := tppService.Participants(r.Context(), session.OrganizationIDs)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting participants", "error", err)
			renderError(w, r, tmpl, err)
			return
		}

		page := struct {
			Participants []tpp.Participant
			Nonce        string
		}{
			Participants: participants,
			Nonce:        secure.CSPNonce(r.Context()),
		}

		if err := tmpl.ExecuteTemplate(w, "servers.html", page); err != nil {
			slog.ErrorContext(r.Context(), "error executing servers template", "error", err)
			renderError(w, r, tmpl, err)
			return
		}
	}
}

func flowsHandler(tmpl *template.Template, tppService *tpp.TPP) sessionHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, session *tpp.Session) {
		slog.InfoContext(r.Context(), "displaying flows")

		orgID := r.PathValue("org_id")
		authServerID := r.PathValue("auth_server_id")

		authServer, err := tppService.AuthServer(r.Context(), authServerID, orgID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting api types", "error", err)
			renderError(w, r, tmpl, err)
			return
		}

		err = tppService.ParticipantDCR(r.Context(), authServer)
		if err != nil {
			slog.ErrorContext(r.Context(), "participant dcr request failed", "error", err)
			renderError(w, r, tmpl, err)
			return
		}

		page := struct {
			AuthServer tpp.AuthServer
			Nonce      string
		}{
			AuthServer: authServer,
			Nonce:      secure.CSPNonce(r.Context()),
		}

		if err := tmpl.ExecuteTemplate(w, "flows.html", page); err != nil {
			slog.ErrorContext(r.Context(), "error executing flows template", "error", err)
			renderError(w, r, tmpl, err)
			return
		}
	}
}

func initFlowHandler(tmpl *template.Template, tppService *tpp.TPP) sessionHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, session *tpp.Session) {
		slog.InfoContext(r.Context(), "initializing flow")

		orgID := r.PathValue("org_id")
		authServerID := r.PathValue("auth_server_id")
		apiType := r.FormValue("api_type")
		apiVersion := r.FormValue("api_version")
		flow := &tpp.Flow{
			UserID:       session.UserID,
			AuthServerID: authServerID,
			OrgID:        orgID,
			APIType:      tpp.APIType(apiType),
			APIVersion:   apiVersion,
		}
		if err := tppService.InitFlow(r.Context(), flow); err != nil {
			slog.ErrorContext(r.Context(), "error initializing flow", "error", err)
			renderError(w, r, tmpl, err)
			return
		}

		redirect(w, "/flows/"+flow.ID)
	}
}

type flowPage struct {
	FlowID       string
	AuthServerID string
	OrgID        string
	APIType      tpp.APIType
	Token        string
	Nonce        string
}

func flowHandler(tmpl *template.Template) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "displaying flow")

		page := flowPage{
			FlowID:       flow.ID,
			AuthServerID: flow.AuthServerID,
			OrgID:        flow.OrgID,
			APIType:      flow.APIType,
			Token:        flow.AuthCodeToken,
			Nonce:        secure.CSPNonce(r.Context()),
		}

		if err := tmpl.ExecuteTemplate(w, "flow.html", page); err != nil {
			slog.ErrorContext(r.Context(), "error executing flow template", "error", err)
			renderFlowError(w, r, tmpl, flow, err)
			return
		}
	}
}

func flowInitAuthHandler(tmpl *template.Template, tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "initializing flow auth")

		if err := r.ParseForm(); err != nil {
			slog.ErrorContext(r.Context(), "error parsing form", "error", err)
			renderFlowError(w, r, tmpl, flow, err)
			return
		}

		permissions := []tpp.Permission{}
		for _, p := range r.PostForm["permissions"] {
			permissions = append(permissions, tpp.Permission(p))
		}
		consent := tpp.Consent{
			UserCPF:      r.FormValue("cpf"),
			BusinessCNPJ: r.FormValue("cnpj"),
			Permissions:  permissions,
		}

		authURL, err := tppService.InitFlowAuth(r.Context(), flow, consent)
		if err != nil {
			tppService.Error(r.Context(), flow.ID, "error initiating participant auth flow", slog.String("error", err.Error()))
			renderFlowError(w, r, tmpl, flow, err)
			return
		}

		redirect(w, authURL)
	}
}

func callbackHandler(tmpl *template.Template, tppService *tpp.TPP) sessionHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, session *tpp.Session) {
		slog.InfoContext(r.Context(), "receiving participant callback")

		response := r.URL.Query().Get("response")
		flow, err := tppService.UnauthorizedFlow(r.Context(), response)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting unauthorized flow", "error", err)
			renderError(w, r, tmpl, err)
			return
		}

		if err := tppService.AuthorizeFlow(r.Context(), flow, response); err != nil {
			tppService.Error(r.Context(), flow.ID, "error authorizing flow", slog.String("error", err.Error()))
			renderFlowError(w, r, tmpl, flow, err)
			return
		}
		tppService.Info(r.Context(), flow.ID, "flow successfully authorized")

		redirect(w, "/flows/"+flow.ID)
	}
}

func customersPersonalIdentificationHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching personal customer identification policies")

		policies, err := tppService.CustomersPersonalIdentifications(r.Context(), flow)
		if err != nil {
			tppService.Error(r.Context(), flow.ID, "error getting personal customer identification policies", slog.String("error", err.Error()))
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func customersPersonalQualificationHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching personal customer qualification policies")

		policies, err := tppService.CustomersPersonalQualifications(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting personal customer qualification policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func customersPersonalAdditionalInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching complimentary personal customer policies")

		policies, err := tppService.CustomersPersonalAdditionalInfo(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting complimentary personal customer policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func customersBusinessIdentificationHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching business customer identification policies")

		policies, err := tppService.CustomersBusinessIdentifications(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting business customer identification policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func customersBusinessQualificationHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching business customer qualification policies")

		policies, err := tppService.CustomersBusinessQualifications(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting business customer qualification policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func customersBusinessAdditionalInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching complimentary business customer policies")

		policies, err := tppService.CustomersBusinessAdditionalInfo(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting complimentary business customer policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func insuranceAutoPoliciesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching auto policies")

		policies, err := tppService.AutoPolicies(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting auto policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func insuranceAutoPolicyInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching auto policy data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.AutoPolicyInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting auto policy data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func insuranceAutoPolicyPremiumHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching auto policy premium data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.AutoPolicyPremium(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting auto policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func insuranceAutoPolicyClaimsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching auto policy claim data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.AutoPolicyClaims(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting auto policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func housingPoliciesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching housing policies")

		policies, err := tppService.HousingPolicies(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting housing policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func acceptanceAndBranchesAbroadPoliciesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching acceptance and branches abroad policies")

		policies, err := tppService.AcceptanceAndBranchesAbroadPolicies(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting acceptance and branches abroad policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func acceptanceAndBranchesAbroadPolicyInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching acceptance and branches abroad policy data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.AcceptanceAndBranchesAbroadPolicyInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting acceptance and branches abroad policy data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func acceptanceAndBranchesAbroadPolicyPremiumHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching acceptance and branches abroad policy premium data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.AcceptanceAndBranchesAbroadPolicyPremium(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting acceptance and branches abroad policy premium", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func acceptanceAndBranchesAbroadPolicyClaimsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching acceptance and branches abroad policy claim data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.AcceptanceAndBranchesAbroadPolicyClaims(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting acceptance and branches abroad policy claims", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func insuranceFinancialAssistanceContractsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching financial assistance contracts")

		policies, err := tppService.FinancialAssistanceContracts(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting financial assistance contracts", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func insuranceFinancialAssistanceContractInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching financial assistance contract data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.FinancialAssistanceContractInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting financial assistance contract data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func insuranceFinancialAssistanceContractMovementsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching financial assistance contract movement data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.FinancialAssistanceContractMovements(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting financial assistance contract movement data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func capitalizationTitlePlansHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching capitalization title plans")

		plans, err := tppService.CapitalizationTitlePlans(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting capitalization title plans", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, plans, http.StatusOK)
	}
}

func capitalizationTitlePlanInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching capitalization title plan data")
		dataID := r.PathValue("data_id")

		plans, err := tppService.CapitalizationTitlePlanInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting capitalization title plan data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, plans, http.StatusOK)
	}
}

func capitalizationTitlePlanEventsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching capitalization title plan events data")
		dataID := r.PathValue("data_id")

		plans, err := tppService.CapitalizationTitlePlanEvents(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting capitalization title plan events", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, plans, http.StatusOK)
	}
}

func capitalizationTitlePlanSettlementsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching capitalization title plan settlements data")
		dataID := r.PathValue("data_id")

		plans, err := tppService.CapitalizationTitlePlanSettlements(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting capitalization title plan settlements", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, plans, http.StatusOK)
	}
}

func flowLogsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching flow logs")

		logs, err := tppService.Logs(r.Context(), flow.ID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting flow logs", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, logs, http.StatusOK)
	}
}

func unauthorizedSessionMiddleware(service *tpp.TPP, next sessionHandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieSessionID)
		if err != nil {
			slog.InfoContext(r.Context(), "session cookie not found", "error", err)
			redirect(w, "/login")
			return
		}

		session, err := service.Session(r.Context(), cookie.Value)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting session", "session_id", cookie.Value, "error", err)
			redirect(w, "/login")
			return
		}

		next(w, r, session)
	})
}

func sessionMiddleware(service *tpp.TPP, next sessionHandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieSessionID)
		if err != nil {
			slog.InfoContext(r.Context(), "session cookie not found", "error", err)
			redirect(w, "/login")
			return
		}

		session, err := service.Session(r.Context(), cookie.Value)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting session", "error", err)
			redirect(w, "/login")
			return
		}

		if session.UserID == "" {
			slog.InfoContext(r.Context(), "session was not authorized", "session_id", session.ID)
			redirect(w, "/login")
			return
		}

		orgID := r.PathValue("org_id")
		if orgID != "" {
			if !slices.Contains(session.OrganizationIDs, orgID) {
				slog.ErrorContext(r.Context(), "invalid org id", "org_id", orgID)
				writeError(w, fmt.Errorf("invalid org id: %s", orgID), http.StatusUnauthorized)
				return
			}
		}

		next(w, r, session)
	})
}

func flowMiddleware(service *tpp.TPP, next flowHandlerFunc) http.Handler {
	return sessionMiddleware(service, func(w http.ResponseWriter, r *http.Request, session *tpp.Session) {
		flowID := r.PathValue("flow_id")
		flow, err := service.Flow(r.Context(), flowID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting flow", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		if flow.UserID != session.UserID {
			slog.ErrorContext(r.Context(), "flow not allowed to user", "flow_id", flowID, "user_id", session.UserID)
			writeError(w, errors.New("flow not allowed"), http.StatusForbidden)
			return
		}

		next(w, r, flow)
	})
}

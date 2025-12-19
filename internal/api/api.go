package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/raidiam/mock-tpp/internal/tpp"
	"github.com/raidiam/mock-tpp/ui"
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
	mux.Handle("GET /logout", sessionMiddleware(tppService, logoutHandler(tmpl, tppService)))
	mux.Handle("GET /auth/directory", directoryAuthHandler(tmpl, tppService))
	mux.Handle("GET /auth/directory/callback", unauthorizedSessionMiddleware(tppService, directoryCallbackHandler(tmpl, tppService)))

	mux.Handle("GET /servers", sessionMiddleware(tppService, serversHandler(tmpl, tppService)))

	mux.Handle("GET /servers/{org_id}/{auth_server_id}/flows", sessionMiddleware(tppService, flowsHandler(tmpl, tppService)))
	mux.Handle("POST /servers/{org_id}/{auth_server_id}/flows", sessionMiddleware(tppService, initFlowHandler(tmpl, tppService)))
	mux.Handle("GET /flows/{flow_id}", flowMiddleware(tppService, flowHandler(tmpl)))
	mux.Handle("POST /flows/{flow_id}", flowMiddleware(tppService, flowInitAuthHandler(tmpl, tppService)))
	mux.Handle("GET /flows/{flow_id}/logs", flowMiddleware(tppService, flowLogsHandler(tppService)))
	mux.Handle("GET /auth/callback", sessionMiddleware(tppService, callbackHandler(tmpl, tppService)))
	mux.Handle("GET /flows/{flow_id}/resources", flowMiddleware(tppService, resourcesHandler(tppService)))
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
	mux.Handle("GET /flows/{flow_id}/insurance-housing-policies", flowMiddleware(tppService, housingPoliciesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-housing-policy-info/{data_id}", flowMiddleware(tppService, housingPolicyInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-housing-policy-premium/{data_id}", flowMiddleware(tppService, housingPolicyPremiumHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-housing-policy-claim/{data_id}", flowMiddleware(tppService, housingPolicyClaimsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-patrimonial-policies", flowMiddleware(tppService, patrimonialPoliciesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-patrimonial-policy-info/{data_id}", flowMiddleware(tppService, patrimonialPolicyInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-patrimonial-policy-premium/{data_id}", flowMiddleware(tppService, patrimonialPolicyPremiumHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-patrimonial-policy-claim/{data_id}", flowMiddleware(tppService, patrimonialPolicyClaimsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-person-policies", flowMiddleware(tppService, personPoliciesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-person-policy-info/{data_id}", flowMiddleware(tppService, personPolicyInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-person-policy-premium/{data_id}", flowMiddleware(tppService, personPolicyPremiumHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-person-policy-claim/{data_id}", flowMiddleware(tppService, personPolicyClaimsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-acceptance-and-branches-abroad-policies", flowMiddleware(tppService, acceptanceAndBranchesAbroadPoliciesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-acceptance-and-branches-abroad-policy-info/{data_id}", flowMiddleware(tppService, acceptanceAndBranchesAbroadPolicyInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-acceptance-and-branches-abroad-policy-premium/{data_id}", flowMiddleware(tppService, acceptanceAndBranchesAbroadPolicyPremiumHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-acceptance-and-branches-abroad-policy-claim/{data_id}", flowMiddleware(tppService, acceptanceAndBranchesAbroadPolicyClaimsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-financial-risk-policies", flowMiddleware(tppService, financialRiskPoliciesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-financial-risk-policy-info/{data_id}", flowMiddleware(tppService, financialRiskPolicyInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-financial-risk-policy-premium/{data_id}", flowMiddleware(tppService, financialRiskPolicyPremiumHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-financial-risk-policy-claim/{data_id}", flowMiddleware(tppService, financialRiskPolicyClaimsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-responsibility-policies", flowMiddleware(tppService, responsibilityPoliciesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-responsibility-policy-info/{data_id}", flowMiddleware(tppService, responsibilityPolicyInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-responsibility-policy-premium/{data_id}", flowMiddleware(tppService, responsibilityPolicyPremiumHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-responsibility-policy-claim/{data_id}", flowMiddleware(tppService, responsibilityPolicyClaimsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-rural-policies", flowMiddleware(tppService, ruralPoliciesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-rural-policy-info/{data_id}", flowMiddleware(tppService, ruralPolicyInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-rural-policy-premium/{data_id}", flowMiddleware(tppService, ruralPolicyPremiumHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-rural-policy-claim/{data_id}", flowMiddleware(tppService, ruralPolicyClaimsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-transport-policies", flowMiddleware(tppService, transportPoliciesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-transport-policy-info/{data_id}", flowMiddleware(tppService, transportPolicyInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-transport-policy-premium/{data_id}", flowMiddleware(tppService, transportPolicyPremiumHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-transport-policy-claim/{data_id}", flowMiddleware(tppService, transportPolicyClaimsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-capitalization-title-plans", flowMiddleware(tppService, capitalizationTitlePlansHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-capitalization-title-plan-info/{data_id}", flowMiddleware(tppService, capitalizationTitlePlanInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-capitalization-title-plan-events/{data_id}", flowMiddleware(tppService, capitalizationTitlePlanEventsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-capitalization-title-plan-settlements/{data_id}", flowMiddleware(tppService, capitalizationTitlePlanSettlementsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/financial-assistance-contracts", flowMiddleware(tppService, insuranceFinancialAssistanceContractsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/financial-assistance-contract-info/{data_id}", flowMiddleware(tppService, insuranceFinancialAssistanceContractInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/financial-assistance-contract-movements/{data_id}", flowMiddleware(tppService, insuranceFinancialAssistanceContractMovementsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-life-pension-contracts", flowMiddleware(tppService, lifePensionContractsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-life-pension-contract-info/{data_id}", flowMiddleware(tppService, lifePensionContractInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-life-pension-contract-movements/{data_id}", flowMiddleware(tppService, lifePensionContractMovementsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-life-pension-contract-portabilities/{data_id}", flowMiddleware(tppService, lifePensionContractPortabilitiesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-life-pension-contract-withdrawals/{data_id}", flowMiddleware(tppService, lifePensionContractWithdrawalsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-life-pension-contract-claim/{data_id}", flowMiddleware(tppService, lifePensionContractClaimHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-pension-plan-contracts", flowMiddleware(tppService, pensionPlanContractsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-pension-plan-contract-info/{data_id}", flowMiddleware(tppService, pensionPlanContractInfoHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-pension-plan-contract-movements/{data_id}", flowMiddleware(tppService, pensionPlanContractMovementsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-pension-plan-contract-portabilities/{data_id}", flowMiddleware(tppService, pensionPlanContractPortabilitiesHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-pension-plan-contract-withdrawals/{data_id}", flowMiddleware(tppService, pensionPlanContractWithdrawalsHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/insurance-pension-plan-contract-claim/{data_id}", flowMiddleware(tppService, pensionPlanContractClaimHandler(tppService)))

	mux.Handle("POST /flows/{flow_id}/quote-auto-lead", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteAutoLead)))
	mux.Handle("PATCH /flows/{flow_id}/quote-auto-lead/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteAutoLead)))
	mux.Handle("POST /flows/{flow_id}/quote-auto", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteAuto)))
	mux.Handle("GET /flows/{flow_id}/quote-auto/{consent_id}", flowMiddleware(tppService, quoteHandler(tppService.QuoteAuto)))
	mux.Handle("PATCH /flows/{flow_id}/quote-auto/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteAuto)))

	mux.Handle("POST /flows/{flow_id}/quote-acceptance-and-branches-abroad-lead", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteAcceptanceAndBranchesAbroadLead)))
	mux.Handle("PATCH /flows/{flow_id}/quote-acceptance-and-branches-abroad-lead/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteAcceptanceAndBranchesAbroadLead)))

	mux.Handle("POST /flows/{flow_id}/quote-patrimonial-lead", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuotePatrimonialLead)))
	mux.Handle("PATCH /flows/{flow_id}/quote-patrimonial-lead/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuotePatrimonialLead)))
	mux.Handle("POST /flows/{flow_id}/quote-patrimonial-business", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuotePatrimonialBusiness)))
	mux.Handle("GET /flows/{flow_id}/quote-patrimonial-business/{consent_id}", flowMiddleware(tppService, quoteHandler(tppService.QuotePatrimonialBusiness)))
	mux.Handle("PATCH /flows/{flow_id}/quote-patrimonial-business/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuotePatrimonialBusiness)))
	mux.Handle("POST /flows/{flow_id}/quote-patrimonial-condominium", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuotePatrimonialCondominium)))
	mux.Handle("GET /flows/{flow_id}/quote-patrimonial-condominium/{consent_id}", flowMiddleware(tppService, quoteHandler(tppService.QuotePatrimonialCondominium)))
	mux.Handle("PATCH /flows/{flow_id}/quote-patrimonial-condominium/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuotePatrimonialCondominium)))
	mux.Handle("POST /flows/{flow_id}/quote-patrimonial-home", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuotePatrimonialHome)))
	mux.Handle("GET /flows/{flow_id}/quote-patrimonial-home/{consent_id}", flowMiddleware(tppService, quoteHandler(tppService.QuotePatrimonialHome)))
	mux.Handle("PATCH /flows/{flow_id}/quote-patrimonial-home/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuotePatrimonialHome)))
	mux.Handle("POST /flows/{flow_id}/quote-patrimonial-diverse-risks", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuotePatrimonialDiverseRisks)))
	mux.Handle("GET /flows/{flow_id}/quote-patrimonial-diverse-risks/{consent_id}", flowMiddleware(tppService, quoteHandler(tppService.QuotePatrimonialDiverseRisks)))
	mux.Handle("PATCH /flows/{flow_id}/quote-patrimonial-diverse-risks/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuotePatrimonialDiverseRisks)))

	mux.Handle("POST /flows/{flow_id}/quote-housing-lead", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteHousingLead)))
	mux.Handle("PATCH /flows/{flow_id}/quote-housing-lead/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteHousingLead)))

	mux.Handle("POST /flows/{flow_id}/quote-financial-risk-lead", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteFinancialRiskLead)))
	mux.Handle("PATCH /flows/{flow_id}/quote-financial-risk-lead/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteFinancialRiskLead)))

	mux.Handle("POST /flows/{flow_id}/quote-responsibility-lead", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteResponsibilityLead)))
	mux.Handle("PATCH /flows/{flow_id}/quote-responsibility-lead/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteResponsibilityLead)))

	mux.Handle("POST /flows/{flow_id}/quote-rural-lead", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteRuralLead)))
	mux.Handle("PATCH /flows/{flow_id}/quote-rural-lead/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteRuralLead)))

	mux.Handle("POST /flows/{flow_id}/quote-transport-lead", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteTransportLead)))
	mux.Handle("PATCH /flows/{flow_id}/quote-transport-lead/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteTransportLead)))

	mux.Handle("POST /flows/{flow_id}/quote-person-lead", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuotePersonLead)))
	mux.Handle("PATCH /flows/{flow_id}/quote-person-lead/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuotePersonLead)))
	mux.Handle("POST /flows/{flow_id}/quote-person-life", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuotePersonLife)))
	mux.Handle("GET /flows/{flow_id}/quote-person-life/{consent_id}", flowMiddleware(tppService, quoteHandler(tppService.QuotePersonLife)))
	mux.Handle("PATCH /flows/{flow_id}/quote-person-life/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuotePersonLife)))
	mux.Handle("POST /flows/{flow_id}/quote-person-travel", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuotePersonTravel)))
	mux.Handle("GET /flows/{flow_id}/quote-person-travel/{consent_id}", flowMiddleware(tppService, quoteHandler(tppService.QuotePersonTravel)))
	mux.Handle("PATCH /flows/{flow_id}/quote-person-travel/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuotePersonTravel)))

	mux.Handle("POST /flows/{flow_id}/quote-capitalization-title-lead", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteCapitalizationTitleLead)))
	mux.Handle("PATCH /flows/{flow_id}/quote-capitalization-title-lead/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteCapitalizationTitleLead)))
	mux.Handle("POST /flows/{flow_id}/quote-capitalization-title", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteCapitalizationTitle)))
	mux.Handle("GET /flows/{flow_id}/quote-capitalization-title/{consent_id}", flowMiddleware(tppService, quoteHandler(tppService.QuoteCapitalizationTitle)))
	mux.Handle("PATCH /flows/{flow_id}/quote-capitalization-title/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteCapitalizationTitle)))
	mux.Handle("POST /flows/{flow_id}/quote-capitalization-title-raffle", flowMiddleware(tppService, createQuoteCapitalizationTitleRaffleHandler(tppService)))

	mux.Handle("POST /flows/{flow_id}/contract-life-pension-lead", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteContractLifePensionLead)))
	mux.Handle("PATCH /flows/{flow_id}/contract-life-pension-lead/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteContractLifePensionLead)))
	mux.Handle("POST /flows/{flow_id}/contract-life-pension", flowMiddleware(tppService, createQuoteHandler(tppService.CreateQuoteContractLifePension)))
	mux.Handle("GET /flows/{flow_id}/contract-life-pension/{consent_id}", flowMiddleware(tppService, quoteHandler(tppService.QuoteContractLifePension)))
	mux.Handle("PATCH /flows/{flow_id}/contract-life-pension/{consent_id}", flowMiddleware(tppService, patchQuoteHandler(tppService.PatchQuoteContractLifePension)))

	mux.Handle("GET /flows/{flow_id}/dynamic-fields-damage-and-person", flowMiddleware(tppService, dynamicFieldsDamageAndPersonHandler(tppService)))
	mux.Handle("GET /flows/{flow_id}/dynamic-fields-capitalization-title", flowMiddleware(tppService, dynamicFieldsCapitalizationTitleHandler(tppService)))

	mux.Handle("POST /flows/{flow_id}/endorsement", flowMiddleware(tppService, createEndorsementHandler(tppService)))

	mux.Handle("POST /flows/{flow_id}/claim-notification-damage", flowMiddleware(tppService, createClaimNotificationDamagesHandler(tppService)))
	mux.Handle("POST /flows/{flow_id}/claim-notification-person", flowMiddleware(tppService, createClaimNotificationPersonHandler(tppService)))

	mux.Handle("POST /flows/{flow_id}/withdrawal-capitalization-title", flowMiddleware(tppService, createWithdrawalCapitalizationTitleHandler(tppService)))
	mux.Handle("POST /flows/{flow_id}/withdrawal-pension-lead", flowMiddleware(tppService, createWithdrawalPensionLeadHandler(tppService)))
	mux.Handle("POST /flows/{flow_id}/withdrawal-pension", flowMiddleware(tppService, createWithdrawalPensionHandler(tppService)))

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

func logoutHandler(tmpl *template.Template, tppService *tpp.TPP) sessionHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, session *tpp.Session) {
		slog.InfoContext(r.Context(), "Logging out from directory")

		endSessionURL, err := tppService.FinalizeSession(r.Context(), session)

		if err != nil {
			slog.ErrorContext(r.Context(), "error finalizing session", "error", err)
			renderError(w, r, tmpl, err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieSessionID,
			Value:    session.ID,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   0,
			Expires:  time.Unix(0, 0),
			Path:     "/",
		})

		redirect(w, endSessionURL)
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
		if r.FormValue("endorsement") == "true" {
			endorsement := tpp.Endorsement{
				PolicyID:           r.FormValue("policy-id"),
				InsuredObjectID:    []string{r.FormValue("insured-object-id")},
				Type:               r.FormValue("type"),
				ProposalID:         r.FormValue("proposal-id"),
				RequestDescription: r.FormValue("request-description"),
			}
			consent.Endorsement = &endorsement
		}
		if r.FormValue("claim-notification") == "true" {
			claimNotification := tpp.ClaimNotification{
				DocumentType:          r.FormValue("document-type"),
				PolicyID:              r.FormValue("policy-id"),
				GroupCertificateID:    r.FormValue("group-certificate-id"),
				InsuredObjectID:       []string{r.FormValue("insured-object-id")},
				ProposalID:            r.FormValue("proposal-id"),
				OccurrenceDate:        r.FormValue("occurrence-date"),
				OccurrenceTime:        r.FormValue("occurrence-time"),
				OccurrenceDescription: r.FormValue("occurrence-description"),
			}
			consent.ClaimNotification = &claimNotification
		}
		if r.FormValue("withdrawal-pension") == "true" {
			withdrawalLifePension := tpp.WithdrawalLifePension{
				CertificateID:          r.FormValue("certificate-id"),
				ProductName:            r.FormValue("product-name"),
				WithdrawalType:         r.FormValue("withdrawal-type"),
				WithdrawalReason:       r.FormValue("withdrawal-reason"),
				WithdrawalReasonOthers: r.FormValue("withdrawal-reason-others"),
				DesiredTotalAmount:     r.FormValue("desired-total-amount"),
				PmbacAmount:            r.FormValue("pmbac-amount"),
			}
			consent.WithdrawalLifePension = &withdrawalLifePension
		}
		if r.FormValue("withdrawal-capitalization-title") == "true" {
			withdrawalCapitalizationTitle := tpp.WithdrawalCapitalizationTitle{
				CapitalizationTitleName: r.FormValue("capitalization-title-name"),
				PlanID:                  r.FormValue("plan-id"),
				TitleID:                 r.FormValue("title-id"),
				SeriesID:                r.FormValue("series-id"),
				TermEndDate:             r.FormValue("term-end-date"),
				WithdrawalReason:        r.FormValue("withdrawal-reason"),
				WithdrawalReasonOthers:  r.FormValue("withdrawal-reason-others"),
				WithdrawalTotalAmount:   r.FormValue("withdrawal-total-amount"),
			}
			consent.WithdrawalCapitalizationTitle = &withdrawalCapitalizationTitle
		}
		if r.FormValue("quote-capitalization-title-raffle") == "true" {
			quoteCapitalizationTitleRaffle := tpp.QuoteCapitalizationTitleRaffle{
				ContactType: r.FormValue("contact-type"),
				Email:       r.FormValue("email"),
				Phone:       r.FormValue("phone"),
			}
			consent.QuoteCapitalizationTitleRaffle = &quoteCapitalizationTitleRaffle
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

func resourcesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching resources")
		pageSize := r.URL.Query().Get("page-size")
		page := r.URL.Query().Get("page")

		resources, err := tppService.Resources(r.Context(), flow, pageSize, page)
		if err != nil {
			tppService.Error(r.Context(), flow.ID, "error getting resources", slog.String("error", err.Error()))
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, resources, http.StatusOK)
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

func housingPolicyInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching housing policy data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.HousingPolicyInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting housing policy data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func housingPolicyPremiumHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching housing policy premium data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.HousingPolicyPremium(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting housing policy premium", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func housingPolicyClaimsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching housing policy claim data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.HousingPolicyClaims(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting housing policy claims", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func patrimonialPoliciesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching patrimonial policies")

		policies, err := tppService.PatrimonialPolicies(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting patrimonial policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func patrimonialPolicyInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching patrimonial policy data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.PatrimonialPolicyInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting patrimonial policy data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func patrimonialPolicyPremiumHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching patrimonial policy premium data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.PatrimonialPolicyPremium(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting patrimonial policy premium", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func patrimonialPolicyClaimsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching patrimonial policy claim data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.PatrimonialPolicyClaims(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting patrimonial policy claims", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func personPoliciesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching person policies")

		policies, err := tppService.PersonPolicies(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting person policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func personPolicyInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching person policy data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.PersonPolicyInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting person policy data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func personPolicyPremiumHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching person policy premium data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.PersonPolicyPremium(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting person policy premium", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func personPolicyClaimsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching person policy claim data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.PersonPolicyClaims(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting person policy claims", "error", err)
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

func responsibilityPoliciesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching responsibility policies")

		policies, err := tppService.ResponsibilityPolicies(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting responsibility policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func responsibilityPolicyInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching responsibility policy data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.ResponsibilityPolicyInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting responsibility policy data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func responsibilityPolicyPremiumHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching responsibility policy premium data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.ResponsibilityPolicyPremium(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting responsibility policy premium", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func responsibilityPolicyClaimsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching responsibility policy claim data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.ResponsibilityPolicyClaims(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting responsibility policy claims", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func ruralPoliciesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching rural policies")

		policies, err := tppService.RuralPolicies(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting rural policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func ruralPolicyInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching rural policy data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.RuralPolicyInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting rural policy data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func ruralPolicyPremiumHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching rural policy premium data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.RuralPolicyPremium(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting rural policy premium", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func ruralPolicyClaimsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching rural policy claim data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.RuralPolicyClaims(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting rural policy claims", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func transportPoliciesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching transport policies")

		policies, err := tppService.TransportPolicies(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting transport policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func transportPolicyInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching transport policy data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.TransportPolicyInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting transport policy data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func transportPolicyPremiumHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching transport policy premium data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.TransportPolicyPremium(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting transport policy premium", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func transportPolicyClaimsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching transport policy claim data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.TransportPolicyClaims(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting transport policy claims", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func financialRiskPoliciesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching financial risk policies")

		policies, err := tppService.FinancialRiskPolicies(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting financial risk policies", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func financialRiskPolicyInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching financial risk policy data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.FinancialRiskPolicyInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting financial risk policy data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func financialRiskPolicyPremiumHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching financial risk policy premium data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.FinancialRiskPolicyPremium(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting financial risk policy premium", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, policies, http.StatusOK)
	}
}

func financialRiskPolicyClaimsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching financial risk policy claim data")
		dataID := r.PathValue("data_id")

		policies, err := tppService.FinancialRiskPolicyClaims(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting financial risk policy claims", "error", err)
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

func lifePensionContractsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching life pension contracts")

		contracts, err := tppService.LifePensionContracts(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting life pension contracts", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
	}
}

func lifePensionContractInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching life pension contract data")
		dataID := r.PathValue("data_id")

		contracts, err := tppService.LifePensionContractInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting life pension contract data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
	}
}

func lifePensionContractMovementsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching life pension contract movements data")
		dataID := r.PathValue("data_id")

		contracts, err := tppService.LifePensionContractMovements(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting life pension contract movements", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
	}
}

func lifePensionContractPortabilitiesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching life pension contract portabilities data")
		dataID := r.PathValue("data_id")

		contracts, err := tppService.LifePensionContractPortabilities(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting life pension contract portabilities", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
	}
}

func lifePensionContractWithdrawalsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching life pension contract withdrawals data")
		dataID := r.PathValue("data_id")

		contracts, err := tppService.LifePensionContractWithdrawals(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting life pension contract withdrawals", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
	}
}

func lifePensionContractClaimHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching life pension contract claim data")
		dataID := r.PathValue("data_id")

		contracts, err := tppService.LifePensionContractClaim(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting life pension contract claim", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
	}
}

func pensionPlanContractsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching life pension contracts")

		contracts, err := tppService.PensionPlanContracts(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting life pension contracts", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
	}
}

func pensionPlanContractInfoHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching pension plan contract data")
		dataID := r.PathValue("data_id")

		contracts, err := tppService.PensionPlanContractInfo(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting pension plan contract data", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
	}
}

func pensionPlanContractMovementsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching pension plan contract movements data")
		dataID := r.PathValue("data_id")

		contracts, err := tppService.PensionPlanContractMovements(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting pension plan contract movements", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
	}
}

func pensionPlanContractPortabilitiesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching pension plan contract portabilities data")
		dataID := r.PathValue("data_id")

		contracts, err := tppService.PensionPlanContractPortabilities(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting pension plan contract portabilities", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
	}
}

func pensionPlanContractWithdrawalsHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching pension plan contract withdrawals data")
		dataID := r.PathValue("data_id")

		contracts, err := tppService.PensionPlanContractWithdrawals(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting pension plan contract withdrawals", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
	}
}

func pensionPlanContractClaimHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "Fetching pension plan contract claim data")
		dataID := r.PathValue("data_id")

		contracts, err := tppService.PensionPlanContractClaim(r.Context(), flow, dataID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting pension plan contract claim", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, contracts, http.StatusOK)
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

func createQuoteHandler(createFunc func(ctx context.Context, flow *tpp.Flow, data map[string]any) (map[string]any, error)) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "creating quote")

		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			slog.ErrorContext(r.Context(), "error decoding request body", "error", err)
			writeError(w, err, http.StatusBadRequest)
			return
		}

		quote, err := createFunc(r.Context(), flow, data)
		if err != nil {
			slog.ErrorContext(r.Context(), "error creating quote", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, quote, http.StatusOK)
	}
}

func quoteHandler(quoteFunc func(ctx context.Context, flow *tpp.Flow, consentID string) (map[string]any, error)) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "getting quote status")
		consentID := r.PathValue("consent_id")
		quote, err := quoteFunc(r.Context(), flow, consentID)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting quote status", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, quote, http.StatusOK)
	}
}

func patchQuoteHandler(patchFunc func(ctx context.Context, flow *tpp.Flow, consentID string, data map[string]any) (map[string]any, error)) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "patching quote")

		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			slog.ErrorContext(r.Context(), "error decoding request body", "error", err)
			writeError(w, err, http.StatusBadRequest)
			return
		}
		consentID := r.PathValue("consent_id")
		quote, err := patchFunc(r.Context(), flow, consentID, data)
		if err != nil {
			slog.ErrorContext(r.Context(), "error patching quote", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, quote, http.StatusOK)
	}
}

func dynamicFieldsDamageAndPersonHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching dynamic fields damage and person")

		fields, err := tppService.DynamicFieldsDamageAndPerson(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting dynamic fields damage and person", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, fields, http.StatusOK)
	}
}

func dynamicFieldsCapitalizationTitleHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "fetching dynamic fields capitalization title")

		fields, err := tppService.DynamicFieldsCapitalizationTitle(r.Context(), flow)
		if err != nil {
			slog.ErrorContext(r.Context(), "error getting dynamic fields capitalization title", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, fields, http.StatusOK)
	}
}

func createEndorsementHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "creating endorsement")

		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			slog.ErrorContext(r.Context(), "error decoding request body", "error", err)
			writeError(w, err, http.StatusBadRequest)
			return
		}

		endorsement, err := tppService.CreateEndorsement(r.Context(), flow, data)
		if err != nil {
			slog.ErrorContext(r.Context(), "error creating endorsement", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, endorsement, http.StatusOK)
	}
}

func createClaimNotificationDamagesHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "creating claim notification damages")

		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			slog.ErrorContext(r.Context(), "error decoding request body", "error", err)
			writeError(w, err, http.StatusBadRequest)
			return
		}
		claimNotification, err := tppService.CreateClaimNotificationDamages(r.Context(), flow, data)
		if err != nil {
			slog.ErrorContext(r.Context(), "error creating claim notification damages", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, claimNotification, http.StatusOK)
	}
}

func createClaimNotificationPersonHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "creating claim notification person")

		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			slog.ErrorContext(r.Context(), "error decoding request body", "error", err)
			writeError(w, err, http.StatusBadRequest)
			return
		}
		claimNotification, err := tppService.CreateClaimNotificationPerson(r.Context(), flow, data)
		if err != nil {
			slog.ErrorContext(r.Context(), "error creating claim notification person", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, claimNotification, http.StatusOK)
	}
}

func createWithdrawalCapitalizationTitleHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "creating withdrawal capitalization title")

		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			slog.ErrorContext(r.Context(), "error decoding request body", "error", err)
			writeError(w, err, http.StatusBadRequest)
			return
		}

		withdrawal, err := tppService.CreateWithdrawalCapitalizationTitle(r.Context(), flow, data)
		if err != nil {
			slog.ErrorContext(r.Context(), "error creating withdrawal capitalization title", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, withdrawal, http.StatusOK)
	}
}

func createWithdrawalPensionLeadHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "creating withdrawal pension lead")

		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			slog.ErrorContext(r.Context(), "error decoding request body", "error", err)
			writeError(w, err, http.StatusBadRequest)
			return
		}
		withdrawal, err := tppService.CreateWithdrawalPensionLead(r.Context(), flow, data)
		if err != nil {
			slog.ErrorContext(r.Context(), "error creating withdrawal pension lead", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, withdrawal, http.StatusOK)
	}
}

func createWithdrawalPensionHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "creating withdrawal pension")

		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			slog.ErrorContext(r.Context(), "error decoding request body", "error", err)
			writeError(w, err, http.StatusBadRequest)
			return
		}

		withdrawal, err := tppService.CreateWithdrawalPension(r.Context(), flow, data)
		if err != nil {
			slog.ErrorContext(r.Context(), "error creating withdrawal pension", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, withdrawal, http.StatusOK)
	}
}

func createQuoteCapitalizationTitleRaffleHandler(tppService *tpp.TPP) flowHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, flow *tpp.Flow) {
		slog.InfoContext(r.Context(), "creating quote capitalization title raffle")

		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			slog.ErrorContext(r.Context(), "error decoding request body", "error", err)
			writeError(w, err, http.StatusBadRequest)
			return
		}
		quoteCapitalizationTitleRaffle, err := tppService.CreateQuoteCapitalizationTitleRaffle(r.Context(), flow, data)
		if err != nil {
			slog.ErrorContext(r.Context(), "error creating quote capitalization title raffle", "error", err)
			writeError(w, err, http.StatusInternalServerError)
			return
		}

		writeJSON(w, quoteCapitalizationTitleRaffle, http.StatusOK)
	}
}

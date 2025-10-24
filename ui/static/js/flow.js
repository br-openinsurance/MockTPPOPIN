async function callApi(endpoint, outputId) {
  const out = document.getElementById(outputId);
  out.textContent = "Loading...";

  try {
    const res = await fetch(endpoint, {
      method: "GET",
      credentials: "include",
    });

    const data = await res.json();
    out.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    out.textContent = "Error: " + err.message;
  }
}

const PERMISSIONS_MAP = {
  "customers-personal": [
    "RESOURCES_READ",
    "CUSTOMERS_PERSONAL_IDENTIFICATIONS_READ",
    "CUSTOMERS_PERSONAL_ADDITIONALINFO_READ",
    "CUSTOMERS_PERSONAL_QUALIFICATION_READ"
  ],
  "customers-business": [
    "RESOURCES_READ",
    "CUSTOMERS_BUSINESS_IDENTIFICATIONS_READ",
    "CUSTOMERS_BUSINESS_ADDITIONALINFO_READ",
    "CUSTOMERS_BUSINESS_QUALIFICATION_READ"
  ],
  "auto": [
    "RESOURCES_READ",
    "DAMAGES_AND_PEOPLE_AUTO_READ",
    "DAMAGES_AND_PEOPLE_AUTO_POLICYINFO_READ",
    "DAMAGES_AND_PEOPLE_AUTO_PREMIUM_READ",
    "DAMAGES_AND_PEOPLE_AUTO_CLAIM_READ"
  ],
  "housing": [
    "RESOURCES_READ",
    "DAMAGES_AND_PEOPLE_HOUSING_READ",
    "DAMAGES_AND_PEOPLE_HOUSING_POLICYINFO_READ",
    "DAMAGES_AND_PEOPLE_HOUSING_PREMIUM_READ",
    "DAMAGES_AND_PEOPLE_HOUSING_CLAIM_READ"
  ],
  "acceptance-and-branches-abroad": [
    "RESOURCES_READ",
    "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_READ",
    "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_POLICYINFO_READ",
    "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_PREMIUM_READ",
    "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_CLAIM_READ"
  ],
  "insurance-capitalization-title": [
    "RESOURCES_READ",
    "CAPITALIZATION_TITLE_READ",
    "CAPITALIZATION_TITLE_PLANINFO_READ",
    "CAPITALIZATION_TITLE_EVENTS_READ",
    "CAPITALIZATION_TITLE_SETTLEMENTS_READ"
  ],
  "insurance-financial-assistance": [
    "RESOURCES_READ",
    "FINANCIAL_ASSISTANCE_READ",
    "FINANCIAL_ASSISTANCE_CONTRACTINFO_READ",
    "FINANCIAL_ASSISTANCE_MOVEMENTS_READ"
  ]
};

function injectPermissions(apiType) {
  const list = document.getElementById('perm-list');
  const hidden = document.getElementById('perm-hidden');
  if (!list || !hidden) return;

  const permissions = PERMISSIONS_MAP[apiType] || [];

  list.innerHTML = '';
  hidden.innerHTML = '';
  permissions.forEach(p => {
    const li = document.createElement('li');
    li.textContent = p;
    li.className = 'text-sm text-gray-700';
    list.appendChild(li);

    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'permissions';
    input.value = p;
    hidden.appendChild(input);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const apiType = document.body.dataset.apiType || "";
  injectPermissions(apiType);

  document.querySelectorAll(".api-call").forEach(button => {
    button.addEventListener("click", () => {
      let endpoint = button.getAttribute("data-endpoint");
      const outputId = button.getAttribute("data-output-id");

      // If endpoint expects dataID, append it from the specific input field
      const dataIdInputId = button.getAttribute("data-id-input");
      if (dataIdInputId) {
        const dataIDInput = document.getElementById(dataIdInputId);
        const dataID = dataIDInput ? dataIDInput.value.trim() : "";
        if (!dataID) {
          alert("Por favor, informe o identificador do recurso.");
          return;
        }
        endpoint = endpoint + "/" + dataID;
      }

      callApi(endpoint, outputId);
    });
  });
});

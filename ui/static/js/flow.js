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

async function callApiWithJson(endpoint, outputId, jsonInputId) {
  const out = document.getElementById(outputId);
  const jsonInput = document.getElementById(jsonInputId);

  if (!jsonInput) {
    out.textContent = "Error: JSON input element not found";
    return;
  }

  out.textContent = "Loading...";

  try {
    // Parse JSON to validate it
    const jsonText = jsonInput.value.trim();
    let jsonData;
    try {
      jsonData = JSON.parse(jsonText);
    } catch (parseErr) {
      out.textContent = "Error: Invalid JSON - " + parseErr.message;
      return;
    }

    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify(jsonData),
    });

    if (!res.ok) {
      const errorText = await res.text();
      try {
        const errorJson = JSON.parse(errorText);
        out.textContent = JSON.stringify(errorJson, null, 2);
      } catch {
        out.textContent = `Error ${res.status}: ${errorText}`;
      }
      return;
    }

    const data = await res.json();
    out.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    out.textContent = "Error: " + err.message;
  }
}

async function callApiWithJsonPatch(endpoint, outputId, jsonInputId) {
  const out = document.getElementById(outputId);
  const jsonInput = document.getElementById(jsonInputId);

  if (!jsonInput) {
    out.textContent = "Error: JSON input element not found";
    return;
  }

  out.textContent = "Loading...";

  try {
    // Parse JSON to validate it
    const jsonText = jsonInput.value.trim();
    let jsonData;
    try {
      jsonData = JSON.parse(jsonText);
    } catch (parseErr) {
      out.textContent = "Error: Invalid JSON - " + parseErr.message;
      return;
    }

    const res = await fetch(endpoint, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify(jsonData),
    });

    if (!res.ok) {
      const errorText = await res.text();
      try {
        const errorJson = JSON.parse(errorText);
        out.textContent = JSON.stringify(errorJson, null, 2);
      } catch {
        out.textContent = `Error ${res.status}: ${errorText}`;
      }
      return;
    }

    const data = await res.json();
    out.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    out.textContent = "Error: " + err.message;
  }
}

const PERMISSIONS_MAP = {
  "customers-personal": {
    "name": "Cadastro de Cliente (Pessoa Física)",
    "permissions": [
      "RESOURCES_READ",
      "CUSTOMERS_PERSONAL_IDENTIFICATIONS_READ",
      "CUSTOMERS_PERSONAL_ADDITIONALINFO_READ",
      "CUSTOMERS_PERSONAL_QUALIFICATION_READ"
    ],
  },
  "customers-business": {
    "name": "Cadastro de Cliente (Pessoa Jurídica)",
    "permissions": [
      "RESOURCES_READ",
      "CUSTOMERS_BUSINESS_IDENTIFICATIONS_READ",
      "CUSTOMERS_BUSINESS_ADDITIONALINFO_READ",
      "CUSTOMERS_BUSINESS_QUALIFICATION_READ"
    ],
  },
  "auto": {
    "name": "Seguro de Automóvel",
    "permissions": [
      "RESOURCES_READ",
      "DAMAGES_AND_PEOPLE_AUTO_READ",
      "DAMAGES_AND_PEOPLE_AUTO_POLICYINFO_READ",
      "DAMAGES_AND_PEOPLE_AUTO_PREMIUM_READ",
      "DAMAGES_AND_PEOPLE_AUTO_CLAIM_READ"
    ],
  },
  "housing": {
    "name": "Seguro de Habitação",
    "permissions": [
      "RESOURCES_READ",
      "DAMAGES_AND_PEOPLE_HOUSING_READ",
      "DAMAGES_AND_PEOPLE_HOUSING_POLICYINFO_READ",
      "DAMAGES_AND_PEOPLE_HOUSING_PREMIUM_READ",
      "DAMAGES_AND_PEOPLE_HOUSING_CLAIM_READ"
    ],
  },
  "patrimonial": {
    "name": "Seguro de Patrimônio",
    "permissions": [
      "RESOURCES_READ",
      "DAMAGES_AND_PEOPLE_PATRIMONIAL_READ",
      "DAMAGES_AND_PEOPLE_PATRIMONIAL_POLICYINFO_READ",
      "DAMAGES_AND_PEOPLE_PATRIMONIAL_PREMIUM_READ",
      "DAMAGES_AND_PEOPLE_PATRIMONIAL_CLAIM_READ"
    ],
  },
  "transport": {
    "name": "Seguro de Transporte",
    "permissions": [
      "RESOURCES_READ",
      "DAMAGES_AND_PEOPLE_TRANSPORT_READ",
      "DAMAGES_AND_PEOPLE_TRANSPORT_POLICYINFO_READ",
      "DAMAGES_AND_PEOPLE_TRANSPORT_PREMIUM_READ",
      "DAMAGES_AND_PEOPLE_TRANSPORT_CLAIM_READ"
    ],
  },
  "rural": {
    "name": "Seguro Rural",
    "permissions": [
      "RESOURCES_READ",
      "DAMAGES_AND_PEOPLE_RURAL_READ",
      "DAMAGES_AND_PEOPLE_RURAL_POLICYINFO_READ",
      "DAMAGES_AND_PEOPLE_RURAL_PREMIUM_READ",
      "DAMAGES_AND_PEOPLE_RURAL_CLAIM_READ"
    ],
  },
  "responsibility": {
    "name": "Seguro de Responsabilidade",
    "permissions": [
      "RESOURCES_READ",
      "DAMAGES_AND_PEOPLE_RESPONSIBILITY_READ",
      "DAMAGES_AND_PEOPLE_RESPONSIBILITY_POLICYINFO_READ",
      "DAMAGES_AND_PEOPLE_RESPONSIBILITY_PREMIUM_READ",
      "DAMAGES_AND_PEOPLE_RESPONSIBILITY_CLAIM_READ"
    ],
  },
  "insurance-person": {
    "name": "Seguro de Pessoa",
    "permissions": [
      "RESOURCES_READ",
      "DAMAGES_AND_PEOPLE_PERSON_READ",
      "DAMAGES_AND_PEOPLE_PERSON_POLICYINFO_READ",
      "DAMAGES_AND_PEOPLE_PERSON_PREMIUM_READ",
      "DAMAGES_AND_PEOPLE_PERSON_CLAIM_READ"
    ],
  },
  "acceptance-and-branches-abroad": {
    "name": "Aceitação e Sucursal no Exterior",
    "permissions": [
      "RESOURCES_READ",
      "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_READ",
      "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_POLICYINFO_READ",
      "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_PREMIUM_READ",
      "DAMAGES_AND_PEOPLE_ACCEPTANCE_AND_BRANCHES_ABROAD_CLAIM_READ"
    ],
  },
  "financial-risk": {
    "name": "Risco Financeiro",
    "permissions": [
      "RESOURCES_READ",
      "DAMAGES_AND_PEOPLE_FINANCIAL_RISKS_READ",
      "DAMAGES_AND_PEOPLE_FINANCIAL_RISKS_POLICYINFO_READ",
      "DAMAGES_AND_PEOPLE_FINANCIAL_RISKS_PREMIUM_READ",
      "DAMAGES_AND_PEOPLE_FINANCIAL_RISKS_CLAIM_READ"
    ],
  },
  "insurance-capitalization-title": {
    "name": "Título de Capitalização",
    "permissions": [
      "RESOURCES_READ",
      "CAPITALIZATION_TITLE_READ",
      "CAPITALIZATION_TITLE_PLANINFO_READ",
      "CAPITALIZATION_TITLE_EVENTS_READ",
      "CAPITALIZATION_TITLE_SETTLEMENTS_READ"
    ],
  },
  "insurance-financial-assistance": {
    "name": "Assistência Financeira",
    "permissions": [
      "RESOURCES_READ",
      "FINANCIAL_ASSISTANCE_READ",
      "FINANCIAL_ASSISTANCE_CONTRACTINFO_READ",
      "FINANCIAL_ASSISTANCE_MOVEMENTS_READ"
    ],
  },
  "insurance-life-pension": {
    "name": "Pensão de Vida",
    "permissions": [
      "RESOURCES_READ",
      "LIFE_PENSION_READ",
      "LIFE_PENSION_CONTRACTINFO_READ",
      "LIFE_PENSION_MOVEMENTS_READ",
      "LIFE_PENSION_PORTABILITIES_READ",
      "LIFE_PENSION_WITHDRAWALS_READ",
      "LIFE_PENSION_CLAIM"
    ],
  },
  "insurance-pension-plan": {
    "name": "Plano de Pensão",
    "permissions": [
      "RESOURCES_READ",
      "PENSION_PLAN_READ",
      "PENSION_PLAN_CONTRACTINFO_READ",
      "PENSION_PLAN_MOVEMENTS_READ",
      "PENSION_PLAN_PORTABILITIES_READ",
      "PENSION_PLAN_WITHDRAWALS_READ",
      "PENSION_PLAN_CLAIM"
    ]
  },
  "endorsement": {
    "name": "Endosso",
    "permissions": [
      "ENDORSEMENT_REQUEST_CREATE"
    ]
  },
  "claim-notification-damages": {
    "name": "Notificação de Sinistro de Danos",
    "permissions": [
      "CLAIM_NOTIFICATION_REQUEST_DAMAGE_CREATE"
    ]
  },
  "claim-notification-person": {
    "name": "Notificação de Sinistro de Pessoa",
    "permissions": [
      "CLAIM_NOTIFICATION_REQUEST_PERSON_CREATE"
    ]
  },
  "withdrawal-capitalization-title": {
    "name": "Resgate de Título de Capitalização",
    "permissions": [
      "CAPITALIZATION_TITLE_WITHDRAWAL_CREATE"
    ]
  },
  "withdrawal-pension": {
    "name": "Resgate de Previdência",
    "permissions": [
      "PENSION_WITHDRAWAL_LEAD_CREATE",
      "PENSION_WITHDRAWAL_CREATE"
    ]
  },
  "quote-capitalization-title-raffle": {
    "name": "Sorteio de Título de Capitalização",
    "permissions": [
      "QUOTE_CAPITALIZATION_TITLE_RAFFLE_CREATE"
    ]
  }
};

function injectPermissions(apiType) {
  const list = document.getElementById('perm-list');
  const hidden = document.getElementById('perm-hidden');
  if (!list || !hidden) return;

  const permissions = PERMISSIONS_MAP[apiType]['permissions'] || [];

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

const btnNotSelectedClass = 'text-sm px-4 py-2 leading-none border rounded text-[#0F570D] border-[#0F570D] hover:border-transparent hover:text-gray-100 hover:bg-[#0F570D] m-1'
const btnSelectedClass = 'text-sm px-4 py-2 leading-none border rounded text-gray-100 bg-[#0F570D] border-transparent hover:text-[#0F570D] hover:border-[#0F570D] m-1'

function injectPermissionButtons(){
  const div = document.getElementById('perm-buttons');
  if (!div) return;

  div.innerHTML = '';
  for(const key in PERMISSIONS_MAP){
    if(!key.startsWith("customers-")){
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = PERMISSIONS_MAP[key]['name'];
      btn.value = key;
      btn.id = key;
      btn.onclick = () => selectPermission(key);
      btn.className = btnNotSelectedClass;
      div.appendChild(btn);
    }
  }

}

function selectPermission(key){
  const btn = document.getElementById(key);

  if(btn.className == btnNotSelectedClass){
    const hidden = document.getElementById('perm-hidden');
    const permissions = PERMISSIONS_MAP[key]['permissions']
    permissions.forEach(p => {
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'permissions';
      input.id = p;
      input.value = p;
      hidden.appendChild(input);
    });
    btn.className = btnSelectedClass;
  }else{
    const hidden = document.getElementById('perm-hidden');
    const permissions = PERMISSIONS_MAP[key]['permissions']
    permissions.forEach(p => {
      const input = document.getElementById(p);
      hidden.removeChild(input);
    });
    btn.className = btnNotSelectedClass;
  }
}

function injectQuoteAutoJson() {
  const textarea = document.getElementById("quote-auto-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data": {
        "consentId": "urn:raidiam:496ce4f9-c861-4bf6-97c5-6991e3cc8389",
        "expirationDateTime": "2025-12-22T18:53:46Z",
        "quoteCustomer": {
          "identificationData": {
            "updateDateTime": "2025-12-15T18:53:46Z",
            "brandName": "Organização A",
            "civilName": "Juan Kaique Cláudio Fernandes",
            "cpfNumber": "76109277673",
            "companyInfo": {
              "cnpjNumber": "01773247000563",
              "name": "Empresa da Organização A"
            },
            "hasBrazilianNationality": true,
            "contact": {
              "postalAddresses": [
                {
                  "address": "Av Naburo Ykesaki, 1270",
                  "townName": "Marília",
                  "countrySubDivision": "SP",
                  "postCode": "10000000",
                  "country": "BRA"
                }
              ]
            }
          },
          "qualificationData": {
            "updateDateTime": "2025-12-15T18:53:46Z",
            "pepIdentification": "NAO_EXPOSTO",
            "lifePensionPlans": "NAO_SE_APLICA"
          },
          "complimentaryInformationData": {
            "updateDateTime": "2025-12-15T18:53:46Z",
            "startDate": "2025-12-15",
            "productsServices": [
              {
                "contract": "string",
                "type": "MICROSSEGUROS"
              }
            ]
          }
        },
        "quoteData": {
          "termStartDate": "2025-12-15",
          "termEndDate": "2025-12-15",
          "insuranceType": "RENOVACAO",
          "currency": "BRL",
          "includesAssistanceServices": false,
          "termType": "ANUAL",
          "isCollectiveStipulated": true,
          "hasAnIndividualItem": true,
          "coverages": [
            {
              "branch": "0111",
              "code": "CASCO_COMPREENSIVA",
              "isSeparateContractingAllowed": false,
              "maxLMI": {
                "amount": "90.85",
                "unitType": "PORCENTAGEM"
              }
            }
          ]
        }
      }
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-auto-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        },
        "status": "ACKN",
        "insurerQuoteId": "6f9e9fb2-6881-49c7-8380-1aeb1a2ac751"
      }
    }, null, 2);
  }
}

function injectQuoteAutoLeadJson() {
  const textarea = document.getElementById("quote-auto-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:b87de332-b467-4705-8ec6-327bf7b6d65b","expirationDateTime":"2025-12-23T10:30:01Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T10:30:01Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T10:30:01Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T10:30:01Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}},"quoteData":{"coverages":[{"branch":"0111","code":"CASCO_COMPREENSIVA","description":"string"}]}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-auto-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectQuoteAcceptanceAndBranchesAbroadLeadJson() {
  const textarea = document.getElementById("quote-acceptance-and-branches-abroad-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:1355b893-95a9-4b33-a6ea-bf2da8fb8fff","expirationDateTime":"2025-12-23T12:30:10Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:30:10Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:30:10Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:30:10Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-acceptance-and-branches-abroad-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectQuotePatrimonialLeadJson() {
  const textarea = document.getElementById("quote-patrimonial-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:b18ea81a-dd6c-445f-bd3f-c69fa7f976ea","expirationDateTime":"2025-12-23T12:47:10Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:47:10Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:47:10Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:47:10Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}},"quoteData":{"coverages":[{"branch":"0111","code":"SERVICOS_EMERGENCIAIS","description":"string"},{"branch":"0111","code":"SERVICOS_DE_CONVENIENCIA","description":"string"},{"branch":"0111","code":"GARANTIA_ESTENDIDA_ORIGINAL","description":"string"},{"branch":"0111","code":"GARANTIA_ESTENDIDA_AMPLIADA","description":"string"},{"branch":"0111","code":"GARANTIA_ESTENDIDA_REDUZIDA","description":"string"},{"branch":"0111","code":"COMPLEMENTACAO_DE_GARANTIA","description":"string"},{"branch":"0111","code":"CESSANTES_LUCRO_BRUTO_LUCRO_LIQUIDO_E_DESPESAS_FIXAS","description":"string"},{"branch":"0111","code":"CESSANTES_LUCRO_LIQUIDO","description":"string"},{"branch":"0111","code":"CESSANTES_DESPESAS_FIXAS","description":"string"},{"branch":"0111","code":"CESSANTES_PERDA_DE_RECEITA_OU_INTERRUPCAO_DE_NEGOCIOS","description":"string"},{"branch":"0111","code":"ENGENHARIA_OBRAS_CIVIS_CONSTRUCAO_E_INSTALACAO_E_MONTAGEM","description":"string"},{"branch":"0111","code":"ENGENHARIA_AFRETAMENTOS_DE_AERONAVES","description":"string"},{"branch":"0111","code":"ENGENHARIA_ARMAZENAGEM_FORA_DO_CANTEIRO_DE_OBRAS_OU_LOCAL_SEGURADO","description":"string"},{"branch":"0111","code":"ENGENHARIA_DANOS_EM_CONSEQUENCIA_DE_ERRO_DE_PROJETO_RISCO_DO_FABRICANTE","description":"string"},{"branch":"0111","code":"ENGENHARIA_DANOS_MORAIS","description":"string"},{"branch":"0111","code":"ENGENHARIA_DESPESAS_COM_DESENTULHO_DO_LOCAL","description":"string"},{"branch":"0111","code":"ENGENHARIA_DESPESAS_DE_SALVAMENTO_E_CONTENCAO_DE_SINISTROS","description":"string"},{"branch":"0111","code":"ENGENHARIA_DESPESAS_EXTRAORDINARIAS","description":"string"},{"branch":"0111","code":"ENGENHARIA_EQUIPAMENTOS_DE_ESCRITORIO_E_INFORMATICA","description":"string"},{"branch":"0111","code":"ENGENHARIA_EQUIPAMENTOS_MOVEIS_OU_ESTACIONARIOS_UTILIZADOS_NA_OBRA","description":"string"},{"branch":"0111","code":"ENGENHARIA_FERRAMENTAS_DE_PEQUENO_E_MEDIO_PORTE","description":"string"},{"branch":"0111","code":"ENGENHARIA_HONORARIOS_DE_PERITO","description":"string"},{"branch":"0111","code":"ENGENHARIA_INCENDIO_APOS_O_TERMINO_DE_OBRAS_ATE_TRINTA_DIAS_EXCETO_PARA_REFORMAS_OU_AMPLIACOES","description":"string"},{"branch":"0111","code":"ENGENHARIA_LUCROS_CESSANTES","description":"string"},{"branch":"0111","code":"ENGENHARIA_MANUTENCAO_AMPLA_ATE_VINTE_E_QUATRO_MESES","description":"string"},{"branch":"0111","code":"ENGENHARIA_MANUTENCAO_SIMPLES_ATE_VINTE_E_QUATRO_MESES","description":"string"},{"branch":"0111","code":"ENGENHARIA_OBRAS_CONCLUIDAS","description":"string"},{"branch":"0111","code":"ENGENHARIA_OBRAS_TEMPORARIAS","description":"string"},{"branch":"0111","code":"ENGENHARIA_OBRAS_INSTALACOES_CONTRATADAS_ACEITAS_E_OU_COLOCADAS_EM_OPERACAO","description":"string"},{"branch":"0111","code":"ENGENHARIA_PROPRIEDADES_CIRCUNVIZINHAS","description":"string"},{"branch":"0111","code":"ENGENHARIA_RECOMPOSICAO_DE_DOCUMENTOS","description":"string"},{"branch":"0111","code":"ENGENHARIA_RESPONSABILIDADE_CIVIL_EMPREGADOR","description":"string"},{"branch":"0111","code":"ENGENHARIA_FUNDACAO","description":"string"},{"branch":"0111","code":"ENGENHARIA_STANDS_DE_VENDA","description":"string"},{"branch":"0111","code":"ENGENHARIA_TRANSPORTE_TERRESTRE","description":"string"},{"branch":"0111","code":"ENGENHARIA_TUMULTOS_GREVES_E_LOCKOUT","description":"string"},{"branch":"0111","code":"BANCOS_DANOS_MATERIAIS_CAUSADOS_AO_COFRE_FORTE","description":"string"},{"branch":"0111","code":"BANCOS_DANOS_MATERIAIS_CAUSADOS_AOS_CAIXAS_ELETRONICOS_ATM","description":"string"},{"branch":"0111","code":"BANCOS_INFIDELIDADE_DE_FUNCIONARIOS","description":"string"},{"branch":"0111","code":"BANCOS_VALORES_NO_INTERIOR_DO_ESTABELECIMENTO_DENTRO_E_OU_FORA_DE_COFRE_FORTE","description":"string"},{"branch":"0111","code":"BANCOS_VALORES_NO_INTERIOR_DE_CAIXAS_ELETRONICOS_ATM","description":"string"},{"branch":"0111","code":"BANCOS_VALORES_EM_MAOS_DE_PORTADORES_EM_TRANSITO","description":"string"},{"branch":"0111","code":"RNO_ALAGAMENTO_INUNDACAO","description":"string"},{"branch":"0111","code":"RNO_ALUGUEL_PERDA_OU_PAGAMENTO","description":"string"},{"branch":"0111","code":"RNO_ANUNCIOS_LUMINOSOS","description":"string"},{"branch":"0111","code":"RNO_BAGAGEM","description":"string"},{"branch":"0111","code":"RNO_BASICA_INCENDIO_RAIO_EXPLOSAO","description":"string"},{"branch":"0111","code":"RNO_BASICA_DANOS_MATERIAIS","description":"string"},{"branch":"0111","code":"RNO_BASICA_DE_OBRAS_CIVIS_EM_CONSTRUCAO_E_INSTALACOES_E_MONTAGENS","description":"string"},{"branch":"0111","code":"RNO_BENS_DE_TERCEIROS_EM_PODER_DO_SEGURADO","description":"string"},{"branch":"0111","code":"RNO_CARGA_DESCARGA_ICAMENTO_E_DESCIDA","description":"string"},{"branch":"0111","code":"RNO_DANOS_ELETRICOS","description":"string"},{"branch":"0111","code":"RNO_DANOS_NA_FABRICACAO","description":"string"},{"branch":"0111","code":"RNO_DERRAME_D_AGUA_OU_OUTRA_SUBSTANCIA_LIQUIDA_DE_INSTALACOES_DE_CHUVEIROS_AUTOMATICOS_SPRINKLERS","description":"string"},{"branch":"0111","code":"RNO_DESMORONAMENTO","description":"string"},{"branch":"0111","code":"RNO_DESPESAS_ADICIONAIS_OUTRAS_DESPESAS","description":"string"},{"branch":"0111","code":"RNO_DESPESAS_EXTRAORDINARIAS","description":"string"},{"branch":"0111","code":"RNO_DESPESAS_FIXA","description":"string"},{"branch":"0111","code":"RNO_DETERIORACAO_DE_MERCADORIAS_EM_AMBIENTES_FRIGORIFICADOS","description":"string"},{"branch":"0111","code":"RNO_EQUIPAMENTOS_ARRENDADOS","description":"string"},{"branch":"0111","code":"RNO_EQUIPAMENTOS_CEDIDOS_A_TERCEIROS","description":"string"},{"branch":"0111","code":"RNO_EQUIPAMENTOS_CINEMATOGRAFICOS_FOTOGRAFICOS_DE_AUDIO_E_VIDEO","description":"string"},{"branch":"0111","code":"RNO_EQUIPAMENTOS_DIVERSOS_OUTRAS_MODALIDADES","description":"string"},{"branch":"0111","code":"RNO_EQUIPAMENTOS_ELETRONICOS","description":"string"},{"branch":"0111","code":"RNO_EQUIPAMENTOS_ESTACIONARIOS","description":"string"},{"branch":"0111","code":"RNO_EQUIPAMENTOS_MOVEIS","description":"string"},{"branch":"0111","code":"RNO_EQUIPAMENTOS_PORTATEIS","description":"string"},{"branch":"0111","code":"RNO_FIDELIDADE_DE_EMPREGADOS","description":"string"},{"branch":"0111","code":"RNO_HONORARIOS_DE_PERITOS","description":"string"},{"branch":"0111","code":"RNO_IMPACTO_DE_VEICULOS_E_QUEDA_DE_AERONAVES","description":"string"},{"branch":"0111","code":"RNO_IMPACTO_DE_VEICULOS_TERRESTRES","description":"string"},{"branch":"0111","code":"RNO_LINHAS_DE_TRANSMISSAO_E_DISTRIBUICAO","description":"string"},{"branch":"0111","code":"RNO_LUCROS_CESSANTES","description":"string"},{"branch":"0111","code":"RNO_MOVIMENTACAO_INTERNA_DE_MERCADORIAS","description":"string"},{"branch":"0111","code":"RNO_PATIOS","description":"string"},{"branch":"0111","code":"RNO_QUEBRA_DE_MAQUINAS","description":"string"},{"branch":"0111","code":"RNO_QUEBRA_DE_VIDROS_ESPELHOS_MARMORES_E_GRANITOS","description":"string"},{"branch":"0111","code":"RNO_RECOMPOSICAO_DE_REGISTROS_E_DOCUMENTOS","description":"string"},{"branch":"0111","code":"RNO_ROUBO_DE_BENS_DE_HOSPEDES","description":"string"},{"branch":"0111","code":"RNO_ROUBO_DE_VALORES_EM_TRANSITO_EM_MAOS_DE_PORTADOR","description":"string"},{"branch":"0111","code":"RNO_ROUBO_E_FURTO_MEDIANTE_ARROMBAMENTO","description":"string"},{"branch":"0111","code":"RNO_ROUBO_E_OU_FURTO_QUALIFICADO_DE_VALORES_NO_INTERIOR_DO_ESTABELECIMENTO_DENTRO_E_OU_FORA_DE_COFRES_FORTES_OU_CAIXAS_FORTES","description":"string"},{"branch":"0111","code":"RNO_TERRORISMO_E_SABOTAGEM","description":"string"},{"branch":"0111","code":"RNO_TUMULTOS_GREVES_LOCKOUT_E_ATOS_DOLOSOS","description":"string"},{"branch":"0111","code":"RNO_VAZAMENTO_DE_TUBULACOES_E_TANQUES","description":"string"},{"branch":"0111","code":"RNO_VAZAMENTO_DE_TUBULACOES_HIDRAULICAS","description":"string"},{"branch":"0111","code":"RNO_VENDAVAL_FURACAO_CICLONE_TORNADO_GRANIZO_QUEDA_DE_AERONAVES_OU_QUAISQUER_OUTROS_ENGENHOS_AEREOS_OU_ESPACIAIS_IMPACTO_DE_VEICULOS_TERRESTRES_E_FUMACA","description":"string"},{"branch":"0111","code":"OUTRAS","description":"string"}]}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-patrimonial-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectQuotePatrimonialBusinessJson() {
  const textarea = document.getElementById("quote-patrimonial-business-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:de5b0435-37e3-4c3f-8a2e-f24c24496521","expirationDateTime":"2025-12-23T12:49:57Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:49:57Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:49:57Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:49:57Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}},"quoteData":{"isCollectiveStipulated":true,"hasOneRiskLocation":true,"termStartDate":"2025-12-16","termEndDate":"2025-12-16","insuranceType":"RENOVACAO","policyId":"111111","insurerId":"insurer_id","currency":"BRL","maxLMG":{"amount":"90.85","unitType":"PORCENTAGEM"},"includesAssistanceServices":false,"claimDescription":"string","beneficiaries":[{"identification":"76109277673","identificationType":"CPF"}],"coverages":[{"branch":"0111","code":"EMPRESARIAL_INCENDIO_QUEDA_DE_RAIO_E_EXPLOSAO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_DANOS_ELETRICOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_VENDAVAL_ATE_FUMACA","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_DESMORONAMENTO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_ALAGAMENTO_E_INUNDACAO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_TUMULTOS_GREVES_LOCKOUT_E_ATOS_DOLOSOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_ROUBO_E_FURTO_QUALIFICADO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_VALORES","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_QUEBRA_DE_VIDROS_ESPELHOS_MARMORES_E_GRANITOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_ANUNCIOS_LUMINOSOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_FIDELIDADE_DE_EMPREGADOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_RECOMPOSICAO_DE_REGISTROS_E_DOCUMENTOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_DETERIORACAO_DE_MERCADORIAS_EM_AMBIENTES_FRIGORIFICADOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_DERRAME","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_VAZAMENTO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_EQUIPAMENTOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_QUEBRA_DE_MAQUINAS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_RESPONSABILIDADE_CIVIL","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_DESPESAS_EXTRAORDINARIAS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_LUCROS_CESSANTES_DESPESAS_FIXAS_LUCRO_LIQUIDO_LUCRO_BRUTO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_PERDA_OU_PAGAMENTO_DE_ALUGUEL","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_PEQUENAS_OBRAS_DE_ENGENHARIA","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"OUTRAS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}}]}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-patrimonial-business-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        },
        "status": "ACKN",
        "insurerQuoteId": "6f9e9fb2-6881-49c7-8380-1aeb1a2ac751"
      }
    }, null, 2);
  }
}

function injectQuotePatrimonialCondominiumJson() {
  const textarea = document.getElementById("quote-patrimonial-condominium-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:16f48fca-4280-405d-9ff5-7b155f1d89ec","expirationDateTime":"2025-12-23T12:51:37Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:51:37Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:51:37Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:51:37Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}},"quoteData":{"mainActivity":"COMERCIO","isLegallyConstituted":true,"condominiumType":true,"termStartDate":"2025-12-16","termEndDate":"2025-12-16","insuranceType":"RENOVACAO","policyId":"111111","insurerId":"insurer_id","currency":"BRL","basicCoverageIndex":"SIMPLES","maxLMG":{"amount":"90.85","unitType":"PORCENTAGEM"},"includesAssistanceServices":false,"claimAmount":{"amount":"90.85","unitType":"PORCENTAGEM"},"claimDescription":"string","insuredObject":{"identification":"76109277673","structuringType":"CONDOMINIO_VERTICAL","propertyType":"CONDOMINIO_RESIDENCIAL_COM_COMERCIO_NO_TERREO","hasElevator":false,"isFullyOrPartiallyListed":false,"numberOfBlocks":"3","condominiumAge":"20","hasReuseOfWater":false,"securityProtection":["CAMERA_CFTV"],"riskLocationInfo":{},"indenizationWithoutDepreciation":true,"wasThereAClaim":false},"coverages":[{"branch":"0111","code":"CONDOMINIAL_COBERTURA_BASICA_SIMPLES","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_COBERTURA_BASICA_AMPLA","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_ANUNCIOS_LUMINOSOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_DANOS_AO_JARDIM","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_DANOS_ELETRICOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_DESMORONAMENTO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_DESPESAS_COM_ALUGUEL","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_EQUIPAMENTOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_FIDELIDADE_DE_EMPREGADOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_IMPACTO_DE_VEICULOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_VIDA_E_ACIDENTES_PESSOAIS_EMPREGADOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_LUCROS_CESSANTES","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_QUEBRA_DE_VIDROS_ESPELHOS_MARMORES_E_GRANITOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_RESPONSABILIDADE_CIVIL","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_ROUBO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_VALORES","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_VAZAMENTO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_VENDAVAL","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_ALAGAMENTO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"CONDOMINIAL_TUMULTO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"OUTRAS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}}]}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-patrimonial-condominium-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        },
        "status": "ACKN",
        "insurerQuoteId": "6f9e9fb2-6881-49c7-8380-1aeb1a2ac751"
      }
    }, null, 2);
  }
}

function injectQuoteHousingLeadJson() {
  const textarea = document.getElementById("quote-housing-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:1355b893-95a9-4b33-a6ea-bf2da8fb8fff","expirationDateTime":"2025-12-23T12:30:10Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:30:10Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:30:10Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:30:10Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-housing-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectQuoteFinancialRiskLeadJson() {
  const textarea = document.getElementById("quote-financial-risk-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:1355b893-95a9-4b33-a6ea-bf2da8fb8fff","expirationDateTime":"2025-12-23T12:30:10Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:30:10Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:30:10Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:30:10Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-financial-risk-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectQuoteResponsibilityLeadJson() {
  const textarea = document.getElementById("quote-responsibility-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:1355b893-95a9-4b33-a6ea-bf2da8fb8fff","expirationDateTime":"2025-12-23T12:30:10Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:30:10Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:30:10Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:30:10Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-responsibility-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectQuoteRuralLeadJson() {
  const textarea = document.getElementById("quote-rural-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:1355b893-95a9-4b33-a6ea-bf2da8fb8fff","expirationDateTime":"2025-12-23T12:30:10Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:30:10Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:30:10Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:30:10Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-rural-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectQuoteTransportLeadJson() {
  const textarea = document.getElementById("quote-transport-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:1355b893-95a9-4b33-a6ea-bf2da8fb8fff","expirationDateTime":"2025-12-23T12:30:10Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:30:10Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:30:10Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:30:10Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-transport-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectQuoteCapitalizationTitleLeadJson() {
  const textarea = document.getElementById("quote-capitalization-title-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:7af68dcf-df6b-4365-83f1-f54bffb3203c","expirationDateTime":"2025-12-24T11:21:46Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-17T11:21:46Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-17T11:21:46Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-17T11:21:46Z","startDate":"2025-12-17","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-capitalization-title-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectQuoteCapitalizationTitleJson() {
  const textarea = document.getElementById("quote-capitalization-title-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:5fa98538-eea5-484f-8972-657629588131","expirationDateTime":"2025-12-24T11:48:21Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-17T11:48:21Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-17T11:48:21Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-17T11:48:21Z","startDate":"2025-12-17","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}},"quoteData":{"modality":"TRADICIONAL","paymentType":"UNICO","singlePayment":{"amount":"1000.00","unitType":"MONETARIO","unit":{"code":"R$","description":"BRL"}}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-capitalization-title-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        },
        "status": "ACKN",
        "insurerQuoteId": "6f9e9fb2-6881-49c7-8380-1aeb1a2ac751"
      }
    }, null, 2);
  }
}

function injectContractLifePensionLeadJson() {
  const textarea = document.getElementById("contract-life-pension-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:1a9f11e6-e447-4c82-ae83-8002950cedea","expirationDateTime":"2025-12-24T11:58:11Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-17T11:58:11Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-17T11:58:11Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-17T11:58:11Z","startDate":"2025-12-17","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("contract-life-pension-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectContractLifePensionJson() {
  const textarea = document.getElementById("contract-life-pension-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:c0a651e5-00ac-46f1-a0f1-9930853adcd0","expirationDateTime":"2025-12-24T11:59:58Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-17T11:59:58Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-17T11:59:58Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-17T11:59:58Z","startDate":"2025-12-17","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}},"quoteData":{"isPortabilityHiringQuote":true,"pensionRiskCoverage":false,"complementaryIdentification":{"isNewPlanHolder":true},"products":[{"initialContribution":{"amount":"2000.00","unitType":"MONETARIO","unit":{"code":"R$","description":"BRL"}},"isContributeMonthly":false,"planType":"PGBL"}],"investorProfile":{"isQualifiedInvestor":false}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("contract-life-pension-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        },
        "status": "ACKN",
        "insurerQuoteId": "6f9e9fb2-6881-49c7-8380-1aeb1a2ac751"
      }
    }, null, 2);
  }
}

function injectQuoteCapitalizationTitleRaffleJson() {
  const textarea = document.getElementById("quote-capitalization-title-raffle-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"modality":"TRADICIONAL","susepProcessNumber":"15414622222222222","contactType":"EMAIL","email":"contact@email.com","phone":{},"cpfCnpjNumber":"76109277673"}
    }, null, 2);
  }
}

function injectQuotePersonLeadJson() {
  const textarea = document.getElementById("quote-person-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:1355b893-95a9-4b33-a6ea-bf2da8fb8fff","expirationDateTime":"2025-12-23T12:30:10Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:30:10Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:30:10Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:30:10Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-person-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectQuotePersonTravelLeadJson() {
  const textarea = document.getElementById("quote-person-travel-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:1355b893-95a9-4b33-a6ea-bf2da8fb8fff","expirationDateTime":"2025-12-23T12:30:10Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:30:10Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:30:10Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:30:10Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-person-travel-lead-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        }
      }
    }, null, 2);
  }
}

function injectQuotePersonLifeJson() {
  const textarea = document.getElementById("quote-person-life-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:1355b893-95a9-4b33-a6ea-bf2da8fb8fff","expirationDateTime":"2025-12-23T12:30:10Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:30:10Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:30:10Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:30:10Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-person-life-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        },
        "status": "ACKN",
        "insurerQuoteId": "6f9e9fb2-6881-49c7-8380-1aeb1a2ac751"
      }
    }, null, 2);
  }
}

function injectQuotePersonTravelJson() {
  const textarea = document.getElementById("quote-person-travel-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:1355b893-95a9-4b33-a6ea-bf2da8fb8fff","expirationDateTime":"2025-12-23T12:30:10Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:30:10Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:30:10Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:30:10Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-person-travel-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        },
        "status": "ACKN",
        "insurerQuoteId": "6f9e9fb2-6881-49c7-8380-1aeb1a2ac751"
      }
    }, null, 2);
  }
}

function injectQuotePatrimonialHomeJson() {
  const textarea = document.getElementById("quote-patrimonial-home-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:a7777770-3048-4f47-a95a-ea6de39e9fe8","expirationDateTime":"2025-12-23T12:52:31Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:52:31Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:52:31Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:52:31Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}},"quoteData":{"hasCommercialActivity":true,"isCollectiveStipulated":false,"hasOneRiskLocation":true,"termStartDate":"2025-12-16","termEndDate":"2025-12-16","insuranceType":"RENOVACAO","policyId":"111111","insurerId":"insurer_id","currency":"BRL","maxLMG":{"amount":"90.85","unitType":"PORCENTAGEM"},"includesAssistanceServices":false,"beneficiaries":[{"identification":"76109277673","identificationType":"CPF"}],"coverages":[{"branch":"0111","code":"EMPRESARIAL_INCENDIO_QUEDA_DE_RAIO_E_EXPLOSAO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_DANOS_ELETRICOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_VENDAVAL_ATE_FUMACA","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_DESMORONAMENTO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_ALAGAMENTO_E_INUNDACAO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_TUMULTOS_GREVES_LOCKOUT_E_ATOS_DOLOSOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_ROUBO_E_FURTO_QUALIFICADO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_VALORES","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_QUEBRA_DE_VIDROS_ESPELHOS_MARMORES_E_GRANITOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_ANUNCIOS_LUMINOSOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_FIDELIDADE_DE_EMPREGADOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_RECOMPOSICAO_DE_REGISTROS_E_DOCUMENTOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_DETERIORACAO_DE_MERCADORIAS_EM_AMBIENTES_FRIGORIFICADOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_DERRAME","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_VAZAMENTO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_EQUIPAMENTOS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_QUEBRA_DE_MAQUINAS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_RESPONSABILIDADE_CIVIL","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_DESPESAS_EXTRAORDINARIAS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_LUCROS_CESSANTES_DESPESAS_FIXAS_LUCRO_LIQUIDO_LUCRO_BRUTO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_PERDA_OU_PAGAMENTO_DE_ALUGUEL","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"EMPRESARIAL_PEQUENAS_OBRAS_DE_ENGENHARIA","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"OUTRAS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}}]}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-patrimonial-home-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        },
        "status": "ACKN",
        "insurerQuoteId": "6f9e9fb2-6881-49c7-8380-1aeb1a2ac751"
      }
    }, null, 2);
  }
}

function injectQuotePatrimonialDiverseRisksJson() {
  const textarea = document.getElementById("quote-diverse-risks-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"consentId":"urn:raidiam:6c2a2855-a598-440b-8313-4e9da01181bb","expirationDateTime":"2025-12-23T12:53:59Z","quoteCustomer":{"identificationData":{"updateDateTime":"2025-12-16T12:53:59Z","brandName":"Organização A","civilName":"Juan Kaique Cláudio Fernandes","cpfNumber":"76109277673","companyInfo":{"cnpjNumber":"01773247000563","name":"Empresa da Organização A"},"hasBrazilianNationality":true,"contact":{"postalAddresses":[{"address":"Av Naburo Ykesaki, 1270","townName":"Marília","countrySubDivision":"SP","postCode":"10000000","country":"BRA"}]}},"qualificationData":{"updateDateTime":"2025-12-16T12:53:59Z","pepIdentification":"NAO_EXPOSTO","lifePensionPlans":"NAO_SE_APLICA"},"complimentaryInformationData":{"updateDateTime":"2025-12-16T12:53:59Z","startDate":"2025-12-16","productsServices":[{"contract":"string","type":"MICROSSEGUROS"}]}},"quoteData":{"termStartDate":"2025-12-16","termEndDate":"2025-12-16","insuranceType":"RENOVACAO","policyId":"111111","insurerId":"insurer_id","currency":"BRL","maxLMG":{"amount":"90.85","unitType":"PORCENTAGEM"},"includesAssistanceServices":false,"productModalityType":true,"isCollectiveStipulated":false,"insuranceTermStartDate":"2025-12-16","insuredObjectType":"EQUIPAMENTO_MOVEL","beneficiaries":[{"identification":"76109277673","identificationType":"CPF"}],"coverages":[{"branch":"0111","code":"DIVERSOS_DANOS_DE_CAUSA_EXTERNA","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"DIVERSOS_DANOS_DE_CAUSA_EXTERNA_E_ROUBO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"DIVERSOS_ROUBO","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}},{"branch":"0111","code":"OUTRAS","isSeparateContractingAllowed":false,"maxLMI":{"amount":"90.85","unitType":"PORCENTAGEM"}}]}}
    }, null, 2);
  }

  const patchTextarea = document.getElementById("quote-diverse-risks-patch-json-input");
  if (patchTextarea) {
    patchTextarea.value = JSON.stringify({
      "data": {
        "author": {
          "identificationType": "CPF",
          "identificationNumber": "76109277673"
        },
        "status": "ACKN",
        "insurerQuoteId": "6f9e9fb2-6881-49c7-8380-1aeb1a2ac751"
      }
    }, null, 2);
  }
}

function injectEndorsementJson() {
  const textarea = document.getElementById("endorsement-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data": {
        "policyId": "0056038d-0f0f-42b1-a6ca-52f97193e7fb",
        "proposalId": "987",
        "endorsementType": "ALTERACAO",
        "requestDescription": "Atualização de apolice para testes funcionais do Open Insurance",
        "requestDate": "2025-12-17",
        "insuredObjectId": ["216731531723"]
      }
    }, null, 2);
  }
}

function injectClaimNotificationJson() {
  const textarea = document.getElementById("claim-notification-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data":{"policyId":"0056038d-0f0f-42b1-a6ca-52f97193e7fb","insuredObjectId":["216731531723"],"documentType":"APOLICE_INDIVIDUAL","occurrenceDate":"2025-12-16","occurrenceTime":"12:00:00","occurrenceDescription":"This is a random string of data"}
    }, null, 2);
  }
}

function injectWithdrawalPensionLeadJson() {
  const textarea = document.getElementById("withdrawal-pension-lead-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data": {
        "generalInfo": {
          "certificateId": "string",
          "productName": "Produto A Previdência"
        },
        "withdrawalInfo": {
          "withdrawalType": "TOTAL",
          "withdrawalReason": "EMERGENCIAS_DE_SAUDE",
          "withdrawalReasonOthers": "string",
          "desiredTotalAmount": {
            "amount": "2000.00",
            "unit": {
              "code": "R$",
              "description": "BRL"
            }
          },
          "pmbacAmount": {
            "amount": "2000.00",
            "unit": {
              "code": "R$",
              "description": "BRL"
            }
          }
        },
        "withdrawalCustomData": {
          "generalInfo": [
            {
              "fieldId": "578-psd-71md6971kjh-2d414",
              "value": "string"
            }
          ],
          "withdrawalInfo": [
            {
              "fieldId": "578-psd-71md6971kjh-2d414",
              "value": "string"
            }
          ]
        }
      }
    }, null, 2);
  }
}

function injectWithdrawalPensionJson() {
  const textarea = document.getElementById("withdrawal-pension-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data": {
        "generalInfo": {
          "certificateId": "string",
          "productName": "Produto A Previdência"
        },
        "withdrawalInfo": {
          "withdrawalType": "TOTAL",
          "withdrawalReason": "EMERGENCIAS_DE_SAUDE",
          "withdrawalReasonOthers": "string",
          "desiredTotalAmount": {
            "amount": "2000.00",
            "unit": {
              "code": "R$",
              "description": "BRL"
            }
          },
          "pmbacAmount": {
            "amount": "2000.00",
            "unit": {
              "code": "R$",
              "description": "BRL"
            }
          }
        },
        "withdrawalCustomData": {
          "generalInfo": [
            {
              "fieldId": "578-psd-71md6971kjh-2d414",
              "value": "string"
            }
          ],
          "withdrawalInfo": [
            {
              "fieldId": "578-psd-71md6971kjh-2d414",
              "value": "string"
            }
          ]
        }
      }
    }, null, 2);
  }
}

function injectWithdrawalCapitalizationTitleJson() {
  const textarea = document.getElementById("withdrawal-capitalization-title-json-input");
  if (textarea) {
    textarea.value = JSON.stringify({
      "data": {
        "modality": "TRADICIONAL",
        "susepProcessNumber": "12345",
        "productInformation": {
          "capitalizationTitleName": "string",
          "planId": "string",
          "titleId": "string",
          "seriesId": "string",
          "termEndDate": "2022-10-27"
        },
        "withdrawalInformation": {
          "withdrawalReason": "IMPOSSIBILIDADE_DE_PAGAMENTO_DAS_PARCELAS",
          "withdrawalReasonOthers": "string",
          "withdrawalTotalAmount": {
            "amount": "2000.00",
            "unit": {
              "code": "R$",
              "description": "BRL"
            }
          }
        },
        "withdrawalCustomData": {
          "customerIdentification": [
            {
              "fieldId": "578-psd-71md6971kjh-2d414",
              "value": "string"
            }
          ],
          "customerQualification": [
            {
              "fieldId": "578-psd-71md6971kjh-2d414",
              "value": "string"
            }
          ],
          "relationshipInfo": [
            {
              "fieldId": "578-psd-71md6971kjh-2d414",
              "value": "string"
            }
          ],
          "productInfo": [
            {
              "fieldId": "578-psd-71md6971kjh-2d414",
              "value": "string"
            }
          ],
          "withdrawalInfo": [
            {
              "fieldId": "578-psd-71md6971kjh-2d414",
              "value": "string"
            }
          ],
          "generalSeriesInfo": [
            {
              "fieldId": "578-psd-71md6971kjh-2d414",
              "value": "string"
            }
          ]
        }
      }
    }, null, 2);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const apiType = document.body.dataset.apiType || "";
  injectPermissions(apiType);
  if(apiType == "resources"){
    injectPermissionButtons()
  }
  if(apiType == "quote-auto"){
    injectQuoteAutoLeadJson()
    injectQuoteAutoJson()
  }
  if(apiType == "quote-acceptance-and-branches-abroad"){
    injectQuoteAcceptanceAndBranchesAbroadLeadJson()
  }
  if(apiType == "quote-patrimonial-business"){
    injectQuotePatrimonialLeadJson()
    injectQuotePatrimonialBusinessJson()
  }
  if(apiType == "quote-patrimonial-condominium"){
    injectQuotePatrimonialLeadJson()
    injectQuotePatrimonialCondominiumJson()
  }
  if(apiType == "quote-patrimonial-home"){
    injectQuotePatrimonialLeadJson()
    injectQuotePatrimonialHomeJson()
  }
  if(apiType == "quote-patrimonial-diverse-risks"){
    injectQuotePatrimonialLeadJson()
    injectQuotePatrimonialDiverseRisksJson()
  }
  if(apiType == "quote-housing"){
    injectQuoteHousingLeadJson()
  }
  if(apiType == "quote-financial-risk"){
    injectQuoteFinancialRiskLeadJson()
  }
  if(apiType == "quote-responsibility"){
    injectQuoteResponsibilityLeadJson()
  }
  if(apiType == "quote-rural"){
    injectQuoteRuralLeadJson()
  }
  if(apiType == "quote-transport"){
    injectQuoteTransportLeadJson()
  }
  if(apiType == "quote-person-life"){
    injectQuotePersonLeadJson()
    injectQuotePersonLifeJson()
  }
  if(apiType == "quote-person-travel"){
    injectQuotePersonTravelLeadJson()
    injectQuotePersonTravelJson()
  }
  if(apiType == "quote-capitalization-title"){
    injectQuoteCapitalizationTitleLeadJson()
    injectQuoteCapitalizationTitleJson()
  }
  if(apiType == "quote-capitalization-title-raffle"){
    injectQuoteCapitalizationTitleRaffleJson()
  }
  if(apiType == "contract-life-pension"){
    injectContractLifePensionLeadJson()
    injectContractLifePensionJson()
  }
  if(apiType == "quote-person-life"){
    injectQuotePersonLeadJson()
    injectQuotePersonLifeJson()
  }
  if(apiType == "quote-person-travel"){
    injectQuotePersonTravelLeadJson()
    injectQuotePersonTravelJson()
  }
  if(apiType == "endorsement"){
    injectEndorsementJson()
  }
  if(apiType == "claim-notification-damages" || apiType == "claim-notification-person"){
    injectClaimNotificationJson()
  }
  if(apiType == "withdrawal-pension"){
    injectWithdrawalPensionLeadJson()
    injectWithdrawalPensionJson()
  }
  if(apiType == "withdrawal-capitalization-title"){
    injectWithdrawalCapitalizationTitleJson()
  }

  document.querySelectorAll(".api-call").forEach(button => {
    button.addEventListener("click", () => {
      let endpoint = button.getAttribute("data-endpoint");
      const outputId = button.getAttribute("data-output-id");

      // If endpoint expects dataID, append it from the specific input field
      const dataIdInputId = button.getAttribute("data-id-input");
      const pageSizeInputId = button.getAttribute("page-size-input");
      const pageInputId = button.getAttribute("page-input");
      if (dataIdInputId) {
        const dataIDInput = document.getElementById(dataIdInputId);
        const dataID = dataIDInput ? dataIDInput.value.trim() : "";
        if (!dataID) {
          alert("Por favor, informe o identificador do recurso.");
          return;
        }
        endpoint = endpoint + "/" + dataID;
      }

      if (pageSizeInputId){
        const pageSizeInput = document.getElementById(pageSizeInputId);
        let pageSize = pageSizeInput ? pageSizeInput.value.trim() : "25";
        pageSize = pageSize == "" ? "25": pageSize
        endpoint = endpoint + "?page-size=" + pageSize
      }
      if (pageInputId){
        const pageInput = document.getElementById(pageInputId);
        let page = pageInput ? pageInput.value.trim() : "1";
        page = page == "" ? "1": page
        endpoint = endpoint + "&page=" + page
      }

      callApi(endpoint, outputId);
    });
  });

  document.querySelectorAll(".api-call-post").forEach(button => {
    button.addEventListener("click", () => {
      const endpoint = button.getAttribute("data-endpoint");
      const outputId = button.getAttribute("data-output-id");
      const jsonInputId = button.getAttribute("data-json-input");

      if (!endpoint || !outputId || !jsonInputId) {
        alert("Configuração inválida do botão.");
        return;
      }

      callApiWithJson(endpoint, outputId, jsonInputId);
    });
  });

  document.querySelectorAll(".api-call-patch").forEach(button => {
    button.addEventListener("click", () => {
      const endpoint = button.getAttribute("data-endpoint");
      const outputId = button.getAttribute("data-output-id");
      const jsonInputId = button.getAttribute("data-json-input");
      const idInputId = button.getAttribute("data-id-input");

      if (!endpoint || !outputId || !jsonInputId || !idInputId) {
        alert("Configuração inválida do botão.");
        return;
      }

      const idInput = document.getElementById(idInputId);
      const consentId = idInput ? idInput.value.trim() : "";
      if (!consentId) {
        alert("Por favor, informe o consent ID.");
        return;
      }

      const fullEndpoint = endpoint + "/" + consentId;
      callApiWithJsonPatch(fullEndpoint, outputId, jsonInputId);
    });
  });
});

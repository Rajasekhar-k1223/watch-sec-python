"""
[v2.8.0] Regulation Applicability Engine
Evaluates organizational profile against jurisdictional thresholds
to determine which of the 32 regulatory frameworks apply.
Does not make conclusive legal claims — flags manual legal review where appropriate.
"""
from typing import Dict, List
from .models import TenantProfile, ApplicabilityResult, ApplicabilityStatus


class ApplicabilityEngine:
    """Evaluates regulatory applicability across all 32 global frameworks"""

    @staticmethod
    def evaluate(profile: TenantProfile) -> Dict[str, ApplicabilityResult]:
        results: Dict[str, ApplicabilityResult] = {}
        countries = set(profile.operating_countries + profile.target_citizen_data + [profile.primary_country])

        def add_res(fid: str, name: str, region: str, status: ApplicabilityStatus, reasoning: str, count: int = 5):
            results[fid] = ApplicabilityResult(
                framework_id=fid,
                name=name,
                region=region,
                status=status,
                reasoning=reasoning,
                mandatory_controls_count=count
            )

        # 1. EU - GDPR
        if "EU" in countries or any(c in countries for c in ["DE", "FR", "NL", "IT", "ES", "IE", "SE", "PL"]):
            add_res("GDPR", "General Data Protection Regulation", "EU", ApplicabilityStatus.APPLICABLE,
                    "Tenant operates in or processes personal data of European Union data subjects (Art. 3 extraterritorial scope).")
        else:
            add_res("GDPR", "General Data Protection Regulation", "EU", ApplicabilityStatus.NOT_APPLICABLE,
                    "No EU operations or citizen personal data processing indicated in profile.")

        # 2. India - DPDP Act 2023
        if "IN" in countries:
            add_res("DPDP_INDIA", "Digital Personal Data Protection Act 2023", "IN", ApplicabilityStatus.APPLICABLE,
                    "Processes digital personal data within India or offers goods/services to data principals in India.")
        else:
            add_res("DPDP_INDIA", "Digital Personal Data Protection Act 2023", "IN", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Indian operations or citizen personal data processing indicated.")

        # 3. USA - CCPA/CPRA
        if "US" in countries:
            if profile.organization_size in ("MID_MARKET", "ENTERPRISE") and profile.industry != "GOVERNMENT":
                add_res("CCPA_CPRA", "California Consumer Privacy Act / CPRA", "US", ApplicabilityStatus.APPLICABLE,
                        "For-profit enterprise doing business in California meeting revenue or consumer record thresholds.")
            else:
                add_res("CCPA_CPRA", "California Consumer Privacy Act / CPRA", "US", ApplicabilityStatus.POTENTIALLY_APPLICABLE,
                        "US operations indicated; subject to statutory revenue ($25M+) or consumer record volume thresholds.")
        else:
            add_res("CCPA_CPRA", "California Consumer Privacy Act / CPRA", "US", ApplicabilityStatus.NOT_APPLICABLE,
                    "No California or US commercial activity declared.")

        # 4. USA - HIPAA
        if profile.processes_health_data or profile.industry == "HEALTHCARE":
            add_res("HIPAA", "Health Insurance Portability and Accountability Act", "US", ApplicabilityStatus.APPLICABLE,
                    "Covered Entity or Business Associate handling Protected Health Information (PHI).")
        elif "US" in countries:
            add_res("HIPAA", "Health Insurance Portability and Accountability Act", "US", ApplicabilityStatus.POTENTIALLY_APPLICABLE,
                    "US entity; applicable if employee wellness, benefits, or medical telemetry is collected.")
        else:
            add_res("HIPAA", "Health Insurance Portability and Accountability Act", "US", ApplicabilityStatus.NOT_APPLICABLE,
                    "No healthcare operations or PHI processing indicated.")

        # 5. USA - GLBA
        if profile.processes_financial_data or profile.industry == "FINANCIAL":
            add_res("GLBA", "Gramm-Leach-Bliley Act (Financial Safeguards)", "US", ApplicabilityStatus.APPLICABLE,
                    "Financial institution significantly engaged in financial activities handling Non-Public Personal Information (NPI).")
        else:
            add_res("GLBA", "Gramm-Leach-Bliley Act (Financial Safeguards)", "US", ApplicabilityStatus.NOT_APPLICABLE,
                    "Not designated as a financial institution under FTC Safeguards Rule.")

        # 6. USA - SOX
        if profile.organization_size == "ENTERPRISE" or profile.industry == "FINANCIAL":
            add_res("SOX", "Sarbanes-Oxley Act (ITGC §404)", "US", ApplicabilityStatus.APPLICABLE,
                    "Publicly traded enterprise or material financial reporting service provider subject to ITGC internal controls.")
        else:
            add_res("SOX", "Sarbanes-Oxley Act (ITGC §404)", "US", ApplicabilityStatus.MANUAL_REVIEW,
                    "Applicability depends on public listing status or supply chain vendor requirements.")

        # 7. USA - FISMA
        if profile.industry == "GOVERNMENT" or profile.critical_infrastructure:
            add_res("FISMA", "Federal Information Security Modernization Act / NIST SP 800-53", "US", ApplicabilityStatus.APPLICABLE,
                    "Federal agency or government contractor operating federal information systems.")
        else:
            add_res("FISMA", "Federal Information Security Modernization Act / NIST SP 800-53", "US", ApplicabilityStatus.NOT_APPLICABLE,
                    "Commercial entity without declared federal contract security baseline mandates.")

        # 8. Brazil - LGPD
        if "BR" in countries:
            add_res("LGPD", "Lei Geral de Proteção de Dados", "BR", ApplicabilityStatus.APPLICABLE,
                    "Processes personal data carried out in Brazil, offering goods/services to Brazilian individuals.")
        else:
            add_res("LGPD", "Lei Geral de Proteção de Dados", "BR", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Brazilian processing activities indicated.")

        # 9, 10, 11. China - PIPL, CSL, DSL
        if "CN" in countries:
            add_res("PIPL", "Personal Information Protection Law", "CN", ApplicabilityStatus.APPLICABLE,
                    "Processes personal information of natural persons within China.")
            add_res("CHINA_CSL", "Cybersecurity Law of the PRC", "CN", ApplicabilityStatus.APPLICABLE,
                    "Operates network facilities or critical information infrastructure in China.")
            add_res("CHINA_DSL", "Data Security Law of the PRC", "CN", ApplicabilityStatus.APPLICABLE,
                    "Conducts data activities within China or impacts PRC national security.")
        else:
            for fid, name in [("PIPL", "Personal Information Protection Law"),
                              ("CHINA_CSL", "Cybersecurity Law"),
                              ("CHINA_DSL", "Data Security Law")]:
                add_res(fid, name, "CN", ApplicabilityStatus.NOT_APPLICABLE, "No mainland China operations indicated.")

        # 12. Japan - APPI
        if "JP" in countries:
            add_res("APPI", "Act on the Protection of Personal Information", "JP", ApplicabilityStatus.APPLICABLE,
                    "Business operator handling personal information of Japanese individuals.")
        else:
            add_res("APPI", "Act on the Protection of Personal Information", "JP", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Japanese operations or citizen data processing indicated.")

        # 13. South Korea - PIPA
        if "KR" in countries:
            add_res("PIPA", "Personal Information Protection Act", "KR", ApplicabilityStatus.APPLICABLE,
                    "Data handler processing personal information of South Korean citizens.")
        else:
            add_res("PIPA", "Personal Information Protection Act", "KR", ApplicabilityStatus.NOT_APPLICABLE,
                    "No South Korean operations indicated.")

        # 14. Singapore - PDPA
        if "SG" in countries:
            add_res("SINGAPORE_PDPA", "Personal Data Protection Act 2012", "SG", ApplicabilityStatus.APPLICABLE,
                    "Collects, uses, or discloses personal data in Singapore.")
        else:
            add_res("SINGAPORE_PDPA", "Personal Data Protection Act 2012", "SG", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Singapore operations indicated.")

        # 15. Thailand - PDPA
        if "TH" in countries:
            add_res("THAILAND_PDPA", "Personal Data Protection Act B.E. 2562", "TH", ApplicabilityStatus.APPLICABLE,
                    "Collection and processing of personal data in Thailand or offering goods/services to Thai data subjects.")
        else:
            add_res("THAILAND_PDPA", "Personal Data Protection Act B.E. 2562", "TH", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Thailand operations indicated.")

        # 16. Indonesia - PDP Law
        if "ID" in countries:
            add_res("INDONESIA_PDP", "Personal Data Protection Law (Law No. 27/2022)", "ID", ApplicabilityStatus.APPLICABLE,
                    "Personal data controller operating in Indonesia or processing Indonesian citizen data.")
        else:
            add_res("INDONESIA_PDP", "Personal Data Protection Law (Law No. 27/2022)", "ID", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Indonesian operations indicated.")

        # 17. Australia - Privacy Act
        if "AU" in countries:
            add_res("AUSTRALIA_PRIVACY", "Privacy Act 1988 & Australian Privacy Principles", "AU", ApplicabilityStatus.APPLICABLE,
                    "APP entity with annual turnover exceeding AUD $3M or health/financial services provider.")
        else:
            add_res("AUSTRALIA_PRIVACY", "Privacy Act 1988 & Australian Privacy Principles", "AU", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Australian operations indicated.")

        # 18. New Zealand - Privacy Act 2020
        if "NZ" in countries:
            add_res("NEW_ZEALAND_PRIVACY", "Privacy Act 2020 (IPPs 1-13)", "NZ", ApplicabilityStatus.APPLICABLE,
                    "Agency carrying on business in New Zealand collecting personal information.")
        else:
            add_res("NEW_ZEALAND_PRIVACY", "Privacy Act 2020 (IPPs 1-13)", "NZ", ApplicabilityStatus.NOT_APPLICABLE,
                    "No New Zealand operations indicated.")

        # 19. Canada - PIPEDA
        if "CA" in countries:
            add_res("PIPEDA", "Personal Information Protection and Electronic Documents Act", "CA", ApplicabilityStatus.APPLICABLE,
                    "Commercial organization collecting, using, or disclosing personal information in Canada.")
        else:
            add_res("PIPEDA", "Personal Information Protection and Electronic Documents Act", "CA", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Canadian commercial activities indicated.")

        # 20. UK - UK GDPR / DPA 2018
        if "GB" in countries or "UK" in countries:
            add_res("UK_GDPR", "UK GDPR & Data Protection Act 2018", "GB", ApplicabilityStatus.APPLICABLE,
                    "Data controller or processor established in the UK or monitoring UK individuals.")
        else:
            add_res("UK_GDPR", "UK GDPR & Data Protection Act 2018", "GB", ApplicabilityStatus.NOT_APPLICABLE,
                    "No UK establishments or UK citizen data processing indicated.")

        # 21. Switzerland - nFADP
        if "CH" in countries:
            add_res("N_FADP", "Swiss Revised Federal Act on Data Protection (nFADP)", "CH", ApplicabilityStatus.APPLICABLE,
                    "Processes personal data producing effects in Switzerland.")
        else:
            add_res("N_FADP", "Swiss Revised Federal Act on Data Protection (nFADP)", "CH", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Swiss processing activities indicated.")

        # 22. Türkiye - KVKK
        if "TR" in countries:
            add_res("KVKK", "Law on Protection of Personal Data (No. 6698)", "TR", ApplicabilityStatus.APPLICABLE,
                    "Data controller processing personal data of Turkish residents.")
        else:
            add_res("KVKK", "Law on Protection of Personal Data (No. 6698)", "TR", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Turkish operations indicated.")

        # 23. South Africa - POPIA
        if "ZA" in countries:
            add_res("POPIA", "Protection of Personal Information Act", "ZA", ApplicabilityStatus.APPLICABLE,
                    "Responsible party domiciled in South Africa or making use of automated means in South Africa.")
        else:
            add_res("POPIA", "Protection of Personal Information Act", "ZA", ApplicabilityStatus.NOT_APPLICABLE,
                    "No South African operations indicated.")

        # 24. Nigeria - NDPA
        if "NG" in countries:
            add_res("NDPA", "Nigeria Data Protection Act 2023", "NG", ApplicabilityStatus.APPLICABLE,
                    "Data controller or processor domiciled in Nigeria or processing data of Nigerian residents.")
        else:
            add_res("NDPA", "Nigeria Data Protection Act 2023", "NG", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Nigerian operations indicated.")

        # 25. Kenya - Data Protection Act
        if "KE" in countries:
            add_res("KENYA_DPA", "Kenya Data Protection Act 2019", "KE", ApplicabilityStatus.APPLICABLE,
                    "Processes personal data of data subjects located in Kenya.")
        else:
            add_res("KENYA_DPA", "Kenya Data Protection Act 2019", "KE", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Kenyan operations indicated.")

        # 26. UAE - Decree-Law 45
        if "AE" in countries:
            add_res("UAE_DPL", "UAE Federal Decree-Law No. 45 of 2021", "AE", ApplicabilityStatus.APPLICABLE,
                    "Processes personal data of UAE data subjects or data controller in UAE.")
        else:
            add_res("UAE_DPL", "UAE Federal Decree-Law No. 45 of 2021", "AE", ApplicabilityStatus.NOT_APPLICABLE,
                    "No UAE operations indicated.")

        # 27. Saudi Arabia - PDPL
        if "SA" in countries:
            add_res("SAUDI_PDPL", "Saudi Personal Data Protection Law", "SA", ApplicabilityStatus.APPLICABLE,
                    "Processes personal data related to individuals residing in the Kingdom of Saudi Arabia.")
        else:
            add_res("SAUDI_PDPL", "Saudi Personal Data Protection Law", "SA", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Saudi Arabian operations indicated.")

        # 28. Qatar - PDPPL
        if "QA" in countries:
            add_res("QATAR_PDPL", "Qatar Personal Data Privacy Protection Law (Law No. 13/2016)", "QA", ApplicabilityStatus.APPLICABLE,
                    "Processes personal data electronically or in Qatar.")
        else:
            add_res("QATAR_PDPL", "Qatar Personal Data Privacy Protection Law (Law No. 13/2016)", "QA", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Qatari operations indicated.")

        # 29. Mexico - LFPDPPP
        if "MX" in countries:
            add_res("MEXICO_LFPDPPP", "Federal Law on Protection of Personal Data (LFPDPPP)", "MX", ApplicabilityStatus.APPLICABLE,
                    "Private physical or legal entity processing personal data in Mexico.")
        else:
            add_res("MEXICO_LFPDPPP", "Federal Law on Protection of Personal Data (LFPDPPP)", "MX", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Mexican operations indicated.")

        # 30. Argentina - PDPL
        if "AR" in countries:
            add_res("ARGENTINA_PDPL", "Personal Data Protection Act (Law 25.326)", "AR", ApplicabilityStatus.APPLICABLE,
                    "Maintains personal data files, registers, or data banks in Argentina.")
        else:
            add_res("ARGENTINA_PDPL", "Personal Data Protection Act (Law 25.326)", "AR", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Argentine operations indicated.")

        # 31. Chile - PDPL
        if "CL" in countries:
            add_res("CHILE_PDPL", "Protection of Private Life Law (Law 19.628)", "CL", ApplicabilityStatus.APPLICABLE,
                    "Natural or legal person responsible for personal data registries in Chile.")
        else:
            add_res("CHILE_PDPL", "Protection of Private Life Law (Law 19.628)", "CL", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Chilean operations indicated.")

        # 32. Colombia - Law 1581
        if "CO" in countries:
            add_res("COLOMBIA_LAW_1581", "Statutory Law 1581 of 2012", "CO", ApplicabilityStatus.APPLICABLE,
                    "Processes personal data in Colombian territory or subject to Colombian law by treaties.")
        else:
            add_res("COLOMBIA_LAW_1581", "Statutory Law 1581 of 2012", "CO", ApplicabilityStatus.NOT_APPLICABLE,
                    "No Colombian operations indicated.")

        return results

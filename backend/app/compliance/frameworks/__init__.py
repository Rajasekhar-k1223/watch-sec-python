"""
[v4.4.0] Global Compliance Frameworks Registry
Registers all 32 core statutory regulations and 18 supplemental security standards
covering Europe, North America, Latin America, Asia-Pacific, Middle East, and Africa.
Provides standardized automated runner functions `run_<framework>_checks()` for all 32 regulations.
"""
from typing import Dict, Type, Optional, List, Any
from sqlalchemy.ext.asyncio import AsyncSession
from .base import BaseComplianceFramework, ComplianceCheckResult

# ---------------------------------------------------------------------------
# 32 Core Statutory Frameworks (Authoritative Global Regulatory Baseline)
# ---------------------------------------------------------------------------
from .gdpr import GdprFramework
from .hipaa import HipaaFramework
from .dpdp import DpdpFramework
from .sox import SoxFramework
from .uk_gdpr import UkGdprFramework
from .ccpa_cpra import CcpaCpraFramework
from .glba import GlbaFramework
from .fisma import FismaFramework
from .lgpd import LgpdFramework
from .pipl import PiplFramework
from .china_csl import ChinaCslFramework
from .china_dsl import ChinaDslFramework
from .appi import AppiFramework
from .pipa import PipaFramework
from .singapore_pdpa import SingaporePdpaFramework
from .thailand_pdpa import ThailandPdpaFramework
from .indonesia_pdp import IndonesiaPdpFramework
from .australia_privacy import AustraliaPrivacyFramework
from .new_zealand_privacy import NewZealandPrivacyFramework
from .pipeda import PipedaFramework
from .n_fadp import NFadpFramework
from .kvkk import KvkkFramework
from .popia import PopiaFramework
from .ndpa import NdpaFramework
from .kenya_dpa import KenyaDpaFramework
from .uae_dpl import UaeDplFramework
from .saudi_pdpl import SaudiPdplFramework
from .qatar_pdpl import QatarPdplFramework
from .mexico_lfpdppp import MexicoLfpdpppFramework
from .ar_pdpa import ArPdpaFramework
from .cl_law_21096 import ClLaw21096Framework
from .co_law_1581 import CoLaw1581Framework

# ---------------------------------------------------------------------------
# Supplemental Industry & Sectoral Security Standards
# ---------------------------------------------------------------------------
from .nis2 import Nis2Framework
from .dora import DoraFramework
from .cra import CraFramework
from .eu_ai_act import EuAiActFramework
from .ny_dfs import NyDfsFramework
from .nist_csf import NistCsfFramework
from .cisa_cross_sector import CisaCrossSectorFramework
from .fedramp import FedrampFramework
from .cmmc import CmmcFramework
from .uk_data_protection import UkDataProtectionFramework
from .uk_nis import UkNisFramework
from .bafin import BafinBaitFramework
from .bsi_c5 import BsiC5Framework
from .anssi_secnumcloud import AnssiSecnumcloudFramework
from .cert_in import CertInFramework
from .rbi_cyber_framework import RbiCyberFramework
from .pci_dss import PciDssFramework
from .iso27001 import Iso27001Framework
from .soc2 import Soc2Framework
from .cis_controls import CisControlsFramework

CORE_32_FRAMEWORK_CLASSES: List[Type[BaseComplianceFramework]] = [
    GdprFramework,                # 1. EU — GDPR
    HipaaFramework,               # 2. USA — HIPAA
    DpdpFramework,                # 3. India — DPDP Act 2023
    SoxFramework,                 # 4. USA — SOX
    UkGdprFramework,              # 5. UK — UK GDPR + DPA 2018
    CcpaCpraFramework,            # 6. USA — CCPA / CPRA
    GlbaFramework,                # 7. USA — GLBA Safeguards Rule
    FismaFramework,               # 8. USA — FISMA / NIST SP 800-53 Rev. 5
    LgpdFramework,                # 9. Brazil — LGPD
    PiplFramework,                # 10. China — PIPL
    ChinaCslFramework,            # 11. China — Cybersecurity Law
    ChinaDslFramework,            # 12. China — Data Security Law
    AppiFramework,                # 13. Japan — APPI
    PipaFramework,                # 14. South Korea — PIPA
    SingaporePdpaFramework,       # 15. Singapore — PDPA
    ThailandPdpaFramework,        # 16. Thailand — PDPA B.E. 2562
    IndonesiaPdpFramework,        # 17. Indonesia — PDP Law No. 27/2022
    AustraliaPrivacyFramework,    # 18. Australia — Privacy Act / APPs 1–13
    NewZealandPrivacyFramework,   # 19. New Zealand — Privacy Act 2020 / IPPs 1–13
    PipedaFramework,              # 20. Canada — PIPEDA (10 Principles)
    NFadpFramework,               # 21. Switzerland — nFADP / revDSG
    KvkkFramework,                # 22. Türkiye — KVKK
    PopiaFramework,               # 23. South Africa — POPIA (8 Conditions)
    NdpaFramework,                # 24. Nigeria — NDPA 2023
    KenyaDpaFramework,            # 25. Kenya — Data Protection Act 2019
    UaeDplFramework,              # 26. UAE — Federal Decree-Law No. 45 of 2021
    SaudiPdplFramework,           # 27. Saudi Arabia — PDPL
    QatarPdplFramework,           # 28. Qatar — Personal Data Privacy Law 13/2016
    MexicoLfpdpppFramework,       # 29. Mexico — LFPDPPP
    ArPdpaFramework,              # 30. Argentina — Ley 25.326 (ARGENTINA_PDPL)
    ClLaw21096Framework,          # 31. Chile — Personal Data Protection Law (CHILE_PDPL)
    CoLaw1581Framework,           # 32. Colombia — Law 1581 of 2012 (COLOMBIA_LAW_1581)
]

SUPPLEMENTAL_FRAMEWORK_CLASSES: List[Type[BaseComplianceFramework]] = [
    Nis2Framework,
    DoraFramework,
    CraFramework,
    EuAiActFramework,
    NyDfsFramework,
    NistCsfFramework,
    CisaCrossSectorFramework,
    FedrampFramework,
    CmmcFramework,
    UkDataProtectionFramework,
    UkNisFramework,
    BafinBaitFramework,
    BsiC5Framework,
    AnssiSecnumcloudFramework,
    CertInFramework,
    RbiCyberFramework,
    PciDssFramework,
    Iso27001Framework,
    Soc2Framework,
    CisControlsFramework,
]

for _supp_cls in SUPPLEMENTAL_FRAMEWORK_CLASSES:
    _supp_cls.is_core_32 = False

for _core_cls in CORE_32_FRAMEWORK_CLASSES:
    _core_cls.is_core_32 = True

ALL_FRAMEWORK_CLASSES: List[Type[BaseComplianceFramework]] = (
    CORE_32_FRAMEWORK_CLASSES + SUPPLEMENTAL_FRAMEWORK_CLASSES
)

CANONICAL_CORE_32_IDS: List[str] = [cls().framework_id for cls in CORE_32_FRAMEWORK_CLASSES]

FRAMEWORK_REGISTRY: Dict[str, Type[BaseComplianceFramework]] = {}
CANONICAL_FRAMEWORK_REGISTRY: Dict[str, Type[BaseComplianceFramework]] = {}

for cls in ALL_FRAMEWORK_CLASSES:
    inst = cls()
    fid = inst.framework_id.upper()
    FRAMEWORK_REGISTRY[fid] = cls
    CANONICAL_FRAMEWORK_REGISTRY[fid] = cls

# Lookup aliases (kept out of canonical posture aggregation to avoid double-counting!)
FRAMEWORK_ALIASES: Dict[str, str] = {
    "EU_GDPR": "GDPR",
    "DPDP": "DPDP_INDIA",
    "INDIA_DPDP": "DPDP_INDIA",
    "CCPA": "CCPA_CPRA",
    "USA_CCPA": "CCPA_CPRA",
    "USA_GLBA": "GLBA",
    "USA_SOX": "SOX",
    "USA_FISMA": "FISMA",
    "USA_HIPAA": "HIPAA",
    "BRAZIL_LGPD": "LGPD",
    "CHINA_PIPL": "PIPL",
    "JAPAN_APPI": "APPI",
    "KOREA_PIPA": "PIPA",
    "AUSTRALIA_APPS": "AUSTRALIA_PRIVACY",
    "NZ_PRIVACY": "NEW_ZEALAND_PRIVACY",
    "CANADA_PIPEDA": "PIPEDA",
    "NFADP": "N_FADP",
    "SWITZERLAND_NFADP": "N_FADP",
    "TURKEY_KVKK": "KVKK",
    "SOUTH_AFRICA_POPIA": "POPIA",
    "NIGERIA_NDPA": "NDPA",
    "MEXICO_PDPL": "MEXICO_LFPDPPP",
    "AR_PDPA": "ARGENTINA_PDPL",
    "ARGENTINA_PDPA": "ARGENTINA_PDPL",
    "ARGENTINA_LPDP": "ARGENTINA_PDPL",
    "CL_LAW_21096": "CHILE_PDPL",
    "CHILE_LAW_21096": "CHILE_PDPL",
    "CHILE_CYBER": "CHILE_PDPL",
    "CHILE_PRIVACY": "CHILE_PDPL",
    "CO_LAW_1581": "COLOMBIA_LAW_1581",
    "COLOMBIA_LEY_1581": "COLOMBIA_LAW_1581",
    "COLOMBIA_PDPL": "COLOMBIA_LAW_1581",
    "NIST_CSF_2": "NIST_CSF",
    "FEDRAMP_REV5": "FEDRAMP",
    "CMMC_2": "CMMC",
    "INDIA_CERT_IN": "CERT_IN",
    "INDIA_RBI_CSF": "RBI_CYBER_SECURITY",
    "EU_CRA": "CRA",
    "NY_DFS_500": "NYDFS_500",
}

for alias, target in FRAMEWORK_ALIASES.items():
    if target in CANONICAL_FRAMEWORK_REGISTRY:
        FRAMEWORK_REGISTRY[alias] = CANONICAL_FRAMEWORK_REGISTRY[target]


def resolve_canonical_framework_id(framework_id: str) -> str:
    upper = framework_id.strip().upper()
    return FRAMEWORK_ALIASES.get(upper, upper)


def get_framework(framework_id: str) -> Optional[BaseComplianceFramework]:
    """Retrieve an instantiated framework by its canonical ID or lookup alias."""
    cls = FRAMEWORK_REGISTRY.get(framework_id.strip().upper())
    return cls() if cls else None


def list_registered_frameworks(include_supplemental: bool = False) -> List[Dict[str, Any]]:
    """
    List metadata for canonical registered compliance frameworks (no duplicate alias entries).
    Defaults to the 32 core statutory regulations; pass `include_supplemental=True` to include
    supplemental security standards (ISO 27001, SOC 2, PCI-DSS, NIS2, DORA, etc.).
    """
    target_classes = ALL_FRAMEWORK_CLASSES if include_supplemental else CORE_32_FRAMEWORK_CLASSES
    out: List[Dict[str, Any]] = []
    seen = set()
    for cls in target_classes:
        inst = cls()
        if inst.framework_id in seen:
            continue
        seen.add(inst.framework_id)
        automated_cnt = sum(
            1 for c in inst.controls if getattr(c.check_type, "value", str(c.check_type)) == "AUTOMATED"
        )
        manual_cnt = len(inst.controls) - automated_cnt
        out.append({
            "id": inst.framework_id,
            "framework_id": inst.framework_id,
            "name": inst.name,
            "region": inst.region,
            "country": inst.region,
            "jurisdiction": inst.jurisdiction,
            "category": inst.category.value if hasattr(inst.category, "value") else str(inst.category),
            "version": inst.version,
            "framework_version": inst.version,
            "effective_from": inst.effective_from,
            "effective_until": inst.effective_until,
            "last_reviewed_at": inst.last_reviewed_at,
            "regulatory_authority": inst.regulatory_authority,
            "breach_notification_window": inst.breach_notification_window,
            "residency_region": inst.residency_region,
            "supported_privacy_rights": inst.supported_privacy_rights,
            "source_reference": inst.source_reference,
            "is_core_32": inst.is_core_32,
            "implementation_status": "IMPLEMENTED",
            "control_count": len(inst.controls),
            "automated_controls_count": automated_cnt,
            "manual_review_controls_count": manual_cnt,
        })
    return out


# ---------------------------------------------------------------------------
# Standardized Automated Framework Runners (All 32 Statutory Regulations)
# ---------------------------------------------------------------------------

async def run_gdpr_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await GdprFramework().run_checks(tenant_id, db, context)

async def run_hipaa_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await HipaaFramework().run_checks(tenant_id, db, context)

async def run_dpdp_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await DpdpFramework().run_checks(tenant_id, db, context)

async def run_sox_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await SoxFramework().run_checks(tenant_id, db, context)

async def run_uk_gdpr_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await UkGdprFramework().run_checks(tenant_id, db, context)

async def run_ccpa_cpra_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await CcpaCpraFramework().run_checks(tenant_id, db, context)

async def run_ccpa_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await CcpaCpraFramework().run_checks(tenant_id, db, context)

async def run_glba_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await GlbaFramework().run_checks(tenant_id, db, context)

async def run_fisma_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await FismaFramework().run_checks(tenant_id, db, context)

async def run_lgpd_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await LgpdFramework().run_checks(tenant_id, db, context)

async def run_pipl_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await PiplFramework().run_checks(tenant_id, db, context)

async def run_china_csl_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await ChinaCslFramework().run_checks(tenant_id, db, context)

async def run_china_dsl_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await ChinaDslFramework().run_checks(tenant_id, db, context)

async def run_appi_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await AppiFramework().run_checks(tenant_id, db, context)

async def run_pipa_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await PipaFramework().run_checks(tenant_id, db, context)

async def run_singapore_pdpa_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await SingaporePdpaFramework().run_checks(tenant_id, db, context)

async def run_thailand_pdpa_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await ThailandPdpaFramework().run_checks(tenant_id, db, context)

async def run_indonesia_pdp_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await IndonesiaPdpFramework().run_checks(tenant_id, db, context)

async def run_australia_privacy_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await AustraliaPrivacyFramework().run_checks(tenant_id, db, context)

async def run_new_zealand_privacy_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await NewZealandPrivacyFramework().run_checks(tenant_id, db, context)

async def run_pipeda_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await PipedaFramework().run_checks(tenant_id, db, context)

async def run_nfadp_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await NFadpFramework().run_checks(tenant_id, db, context)

async def run_n_fadp_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await NFadpFramework().run_checks(tenant_id, db, context)

async def run_kvkk_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await KvkkFramework().run_checks(tenant_id, db, context)

async def run_popia_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await PopiaFramework().run_checks(tenant_id, db, context)

async def run_ndpa_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await NdpaFramework().run_checks(tenant_id, db, context)

async def run_kenya_dpa_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await KenyaDpaFramework().run_checks(tenant_id, db, context)

async def run_uae_dpl_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await UaeDplFramework().run_checks(tenant_id, db, context)

async def run_saudi_pdpl_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await SaudiPdplFramework().run_checks(tenant_id, db, context)

async def run_qatar_pdpl_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await QatarPdplFramework().run_checks(tenant_id, db, context)

async def run_mexico_lfpdppp_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await MexicoLfpdpppFramework().run_checks(tenant_id, db, context)

async def run_argentina_pdpl_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await ArPdpaFramework().run_checks(tenant_id, db, context)

async def run_chile_pdpl_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await ClLaw21096Framework().run_checks(tenant_id, db, context)

async def run_colombia_law_1581_checks(tenant_id: int = 1, db: Optional[AsyncSession] = None, context: Optional[Dict[str, Any]] = None) -> List[ComplianceCheckResult]:
    return await CoLaw1581Framework().run_checks(tenant_id, db, context)


FRAMEWORK_RUNNER_MAP = {
    "GDPR": run_gdpr_checks,
    "HIPAA": run_hipaa_checks,
    "DPDP_INDIA": run_dpdp_checks,
    "SOX": run_sox_checks,
    "UK_GDPR": run_uk_gdpr_checks,
    "CCPA_CPRA": run_ccpa_cpra_checks,
    "GLBA": run_glba_checks,
    "FISMA": run_fisma_checks,
    "LGPD": run_lgpd_checks,
    "PIPL": run_pipl_checks,
    "CHINA_CSL": run_china_csl_checks,
    "CHINA_DSL": run_china_dsl_checks,
    "APPI": run_appi_checks,
    "PIPA": run_pipa_checks,
    "SINGAPORE_PDPA": run_singapore_pdpa_checks,
    "THAILAND_PDPA": run_thailand_pdpa_checks,
    "INDONESIA_PDP": run_indonesia_pdp_checks,
    "AUSTRALIA_PRIVACY": run_australia_privacy_checks,
    "NEW_ZEALAND_PRIVACY": run_new_zealand_privacy_checks,
    "PIPEDA": run_pipeda_checks,
    "N_FADP": run_n_fadp_checks,
    "KVKK": run_kvkk_checks,
    "POPIA": run_popia_checks,
    "NDPA": run_ndpa_checks,
    "KENYA_DPA": run_kenya_dpa_checks,
    "UAE_DPL": run_uae_dpl_checks,
    "SAUDI_PDPL": run_saudi_pdpl_checks,
    "QATAR_PDPL": run_qatar_pdpl_checks,
    "MEXICO_LFPDPPP": run_mexico_lfpdppp_checks,
    "ARGENTINA_PDPL": run_argentina_pdpl_checks,
    "CHILE_PDPL": run_chile_pdpl_checks,
    "COLOMBIA_LAW_1581": run_colombia_law_1581_checks,
}

__all__ = [
    "CORE_32_FRAMEWORK_CLASSES",
    "SUPPLEMENTAL_FRAMEWORK_CLASSES",
    "ALL_FRAMEWORK_CLASSES",
    "CANONICAL_CORE_32_IDS",
    "FRAMEWORK_REGISTRY",
    "CANONICAL_FRAMEWORK_REGISTRY",
    "FRAMEWORK_ALIASES",
    "FRAMEWORK_RUNNER_MAP",
    "resolve_canonical_framework_id",
    "get_framework",
    "list_registered_frameworks",
    "run_gdpr_checks",
    "run_hipaa_checks",
    "run_dpdp_checks",
    "run_sox_checks",
    "run_uk_gdpr_checks",
    "run_ccpa_cpra_checks",
    "run_ccpa_checks",
    "run_glba_checks",
    "run_fisma_checks",
    "run_lgpd_checks",
    "run_pipl_checks",
    "run_china_csl_checks",
    "run_china_dsl_checks",
    "run_appi_checks",
    "run_pipa_checks",
    "run_singapore_pdpa_checks",
    "run_thailand_pdpa_checks",
    "run_indonesia_pdp_checks",
    "run_australia_privacy_checks",
    "run_new_zealand_privacy_checks",
    "run_pipeda_checks",
    "run_nfadp_checks",
    "run_n_fadp_checks",
    "run_kvkk_checks",
    "run_popia_checks",
    "run_ndpa_checks",
    "run_kenya_dpa_checks",
    "run_uae_dpl_checks",
    "run_saudi_pdpl_checks",
    "run_qatar_pdpl_checks",
    "run_mexico_lfpdppp_checks",
    "run_argentina_pdpl_checks",
    "run_chile_pdpl_checks",
    "run_colombia_law_1581_checks",
]

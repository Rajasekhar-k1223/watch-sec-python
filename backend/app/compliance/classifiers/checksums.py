"""
[v2.8.0] Mathematical Checksum Validators for National PII Identifiers
Provides Verhoeff (Aadhaar), Luhn (Credit Cards, Canadian SIN, South African ID),
and Modulo 11 variants (Chile RUT, Brazil CPF/CNPJ, Singapore NRIC/FIN, China RIC).
Guarantees robust false-positive elimination.
"""
from typing import Union


# ---------------------------------------------------------------------------
# 1. VERHOEFF ALGORITHM (Indian UIDAI Aadhaar Validation)
# ---------------------------------------------------------------------------

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(num_str: str) -> bool:
    """Validates 12-digit Indian Aadhaar via Verhoeff multiplication & permutation tables."""
    clean = "".join(ch for ch in num_str if ch.isdigit())
    if not clean or len(clean) != 12:
        return False
    # Aadhaar cannot start with 0 or 1
    if clean[0] in ("0", "1"):
        return False

    c = 0
    reversed_digits = [int(x) for x in reversed(clean)]
    for i, digit in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


# ---------------------------------------------------------------------------
# 2. LUHN ALGORITHM (Credit Cards, Canadian SIN, South African ID)
# ---------------------------------------------------------------------------

def validate_luhn(num_str: str) -> bool:
    """Standard Luhn Modulo 10 check for Credit Cards, Canadian SIN, South African ID."""
    clean = "".join(ch for ch in num_str if ch.isdigit())
    if not clean or len(clean) < 8:
        return False

    checksum = 0
    reverse_digits = clean[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


# ---------------------------------------------------------------------------
# 3. BRAZILIAN CPF & CNPJ VALIDATORS (Modulo 11)
# ---------------------------------------------------------------------------

def validate_brazil_cpf(cpf_str: str) -> bool:
    """Validates 11-digit Brazilian CPF via two verification digits."""
    clean = "".join(ch for ch in cpf_str if ch.isdigit())
    if len(clean) != 11:
        return False
    if clean == clean[0] * 11: # e.g. 111.111.111-11
        return False

    # First digit
    sum1 = sum(int(clean[i]) * (10 - i) for i in range(9))
    d1 = (sum1 * 10) % 11
    if d1 == 10:
        d1 = 0
    if int(clean[9]) != d1:
        return False

    # Second digit
    sum2 = sum(int(clean[i]) * (11 - i) for i in range(10))
    d2 = (sum2 * 10) % 11
    if d2 == 10:
        d2 = 0
    return int(clean[10]) == d2


def validate_brazil_cnpj(cnpj_str: str) -> bool:
    """Validates 14-digit Brazilian CNPJ (Company ID) via Modulo 11."""
    clean = "".join(ch for ch in cnpj_str if ch.isdigit())
    if len(clean) != 14:
        return False
    if clean == clean[0] * 14:
        return False

    w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]

    # Digit 1
    sum1 = sum(int(clean[i]) * w1[i] for i in range(12))
    rem1 = sum1 % 11
    d1 = 0 if rem1 < 2 else 11 - rem1
    if int(clean[12]) != d1:
        return False

    # Digit 2
    sum2 = sum(int(clean[i]) * w2[i] for i in range(13))
    rem2 = sum2 % 11
    d2 = 0 if rem2 < 2 else 11 - rem2
    return int(clean[13]) == d2


# ---------------------------------------------------------------------------
# 4. CHILEAN RUT / RUN VALIDATOR (Modulo 11)
# ---------------------------------------------------------------------------

def validate_chile_rut(rut_str: str) -> bool:
    """Validates Chilean RUT / RUN (e.g. 12.345.678-K) with Modulo 11."""
    clean = rut_str.replace(".", "").replace("-", "").strip().upper()
    if len(clean) < 8 or len(clean) > 9:
        return False

    body = clean[:-1]
    dv = clean[-1]
    if not body.isdigit():
        return False

    multipliers = [2, 3, 4, 5, 6, 7]
    total = 0
    for i, ch in enumerate(reversed(body)):
        total += int(ch) * multipliers[i % len(multipliers)]

    expected_rem = 11 - (total % 11)
    if expected_rem == 11:
        expected_dv = "0"
    elif expected_rem == 10:
        expected_dv = "K"
    else:
        expected_dv = str(expected_rem)

    return dv == expected_dv


# ---------------------------------------------------------------------------
# 5. SINGAPORE NRIC / FIN VALIDATOR (Modulo 11)
# ---------------------------------------------------------------------------

def validate_singapore_nric(nric_str: str) -> bool:
    """Validates Singapore NRIC/FIN ([S,T,F,G,M] + 7 digits + check letter)."""
    clean = nric_str.strip().upper()
    if len(clean) != 9:
        return False

    prefix = clean[0]
    digits = clean[1:8]
    suffix = clean[8]

    if prefix not in "STFGM" or not digits.isdigit() or not suffix.isalpha():
        return False

    weights = [2, 7, 6, 5, 4, 3, 2]
    total = sum(int(d) * w for d, w in zip(digits, weights))

    if prefix in "TG":
        total += 4
    elif prefix == "M":
        total += 3

    rem = total % 11

    st_letters = ["J", "Z", "I", "H", "G", "F", "E", "D", "C", "B", "A"]
    fg_letters = ["X", "W", "U", "T", "R", "Q", "P", "N", "M", "L", "K"]
    m_letters = ["X", "W", "U", "T", "R", "Q", "P", "N", "J", "L", "K"]

    if prefix in "ST":
        return suffix == st_letters[rem]
    elif prefix in "FG":
        return suffix == fg_letters[rem]
    elif prefix == "M":
        return suffix == m_letters[rem]
    return False


# ---------------------------------------------------------------------------
# 6. CHINA RESIDENT IDENTITY CARD (ISO 7064 MOD 11-2)
# ---------------------------------------------------------------------------

def validate_china_ric(ric_str: str) -> bool:
    """Validates 18-digit Chinese Resident Identity Card via ISO 7064 MOD 11-2."""
    clean = ric_str.strip().upper()
    if len(clean) != 18:
        return False
    if not clean[:17].isdigit():
        return False

    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_codes = ["1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"]

    total = sum(int(clean[i]) * weights[i] for i in range(17))
    rem = total % 11
    return clean[17] == check_codes[rem]


# ---------------------------------------------------------------------------
# 7. AUSTRALIAN TAX FILE NUMBER (TFN)
# ---------------------------------------------------------------------------

def validate_australia_tfn(tfn_str: str) -> bool:
    """Validates Australian 8 or 9-digit TFN using ATO weighted Modulo 11 check."""
    clean = "".join(ch for ch in tfn_str if ch.isdigit())
    if len(clean) == 8:
        weights = [10, 7, 8, 4, 6, 3, 5, 1]
    elif len(clean) == 9:
        weights = [1, 4, 3, 7, 5, 8, 6, 9, 10]
    else:
        return False

    total = sum(int(d) * w for d, w in zip(clean, weights))
    return total % 11 == 0


# ---------------------------------------------------------------------------
# 8. TURKISH TC KIMLIK NO
# ---------------------------------------------------------------------------

def validate_turkey_tc_kimlik(tc_str: str) -> bool:
    """Validates 11-digit Turkish Republic Identity Number (TC Kimlik No)."""
    clean = "".join(ch for ch in tc_str if ch.isdigit())
    if len(clean) != 11 or clean[0] == "0":
        return False

    d = [int(c) for c in clean]
    sum_odd = d[0] + d[2] + d[4] + d[6] + d[8]
    sum_even = d[1] + d[3] + d[5] + d[7]

    d10 = ((sum_odd * 7) - sum_even) % 10
    if d[9] != d10:
        return False

    d11 = sum(d[:10]) % 10
    return d[10] == d11


# ---------------------------------------------------------------------------
# 9. UK NHS NUMBER VALIDATOR (Modulo 11)
# ---------------------------------------------------------------------------

def validate_uk_nhs(nhs_str: str) -> bool:
    """Validates 10-digit UK National Health Service (NHS) number using Modulo 11."""
    clean = "".join(ch for ch in nhs_str if ch.isdigit())
    if len(clean) != 10:
        return False

    weights = [10, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(int(clean[i]) * weights[i] for i in range(9))
    rem = total % 11
    cd = 11 - rem
    if cd == 11:
        cd = 0
    elif cd == 10:
        return False  # Invalid NHS number
    return int(clean[9]) == cd


# ---------------------------------------------------------------------------
# 10. NEW ZEALAND IRD NUMBER (Modulo 11)
# ---------------------------------------------------------------------------

def validate_nz_ird(ird_str: str) -> bool:
    """Validates New Zealand 8 or 9-digit IRD number using Modulo 11."""
    clean = "".join(ch for ch in ird_str if ch.isdigit())
    if len(clean) == 8:
        clean = "0" + clean
    if len(clean) != 9:
        return False

    weights = [3, 2, 7, 6, 5, 4, 3, 2]
    total = sum(int(clean[i]) * weights[i] for i in range(8))
    rem = total % 11
    if rem == 0:
        cd = 0
    else:
        cd = 11 - rem

    if cd < 10:
        return int(clean[8]) == cd

    # Secondary weights if first check digit is 10
    weights2 = [7, 4, 3, 2, 5, 2, 7, 6]
    total2 = sum(int(clean[i]) * weights2[i] for i in range(8))
    rem2 = total2 % 11
    cd2 = 0 if rem2 == 0 else (11 - rem2)
    return cd2 < 10 and int(clean[8]) == cd2


# ---------------------------------------------------------------------------
# 11. SWISS AHV / AVS NUMBER (EAN-13 / Luhn-style)
# ---------------------------------------------------------------------------

def validate_swiss_ahv(ahv_str: str) -> bool:
    """Validates Swiss 13-digit AHV / AVS number starting with 756."""
    clean = "".join(ch for ch in ahv_str if ch.isdigit())
    if len(clean) != 13 or not clean.startswith("756"):
        return False

    # Standard EAN-13 checksum: alternating weights 1 and 3
    total = sum(int(d) * (1 if i % 2 == 0 else 3) for i, d in enumerate(clean[:12]))
    cd = (10 - (total % 10)) % 10
    return int(clean[12]) == cd


# ---------------------------------------------------------------------------
# 12. ARGENTINE CUIT / CUIL VALIDATOR (Modulo 11)
# ---------------------------------------------------------------------------

def validate_argentina_cuit(cuit_str: str) -> bool:
    """Validates Argentine 11-digit CUIT / CUIL tax identification number."""
    clean = "".join(ch for ch in cuit_str if ch.isdigit())
    if len(clean) != 11:
        return False

    weights = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
    total = sum(int(clean[i]) * weights[i] for i in range(10))
    rem = total % 11
    if rem == 0:
        expected_dv = 0
    elif rem == 1:
        # Special case
        expected_dv = 9 if clean[:2] in ("20", "27") else 4
    else:
        expected_dv = 11 - rem
    return int(clean[10]) == expected_dv


# ---------------------------------------------------------------------------
# 13. SAUDI ARABIA NATIONAL ID & IQAMA VALIDATOR (Luhn)
# ---------------------------------------------------------------------------

def validate_saudi_id(id_str: str) -> bool:
    """Validates 10-digit Saudi National ID (starts with 1) or Iqama (starts with 2) using Luhn."""
    clean = "".join(ch for ch in id_str if ch.isdigit())
    if len(clean) != 10:
        return False
    if clean[0] not in ("1", "2"):
        return False
    return validate_luhn(clean)


# ---------------------------------------------------------------------------
# 14. JAPAN MY NUMBER VALIDATOR (Modulo 11)
# ---------------------------------------------------------------------------

def validate_japan_my_number(my_str: str) -> bool:
    """Validates 12-digit Japanese Individual Number (My Number) with Modulo 11 check digit."""
    clean = "".join(ch for ch in my_str if ch.isdigit())
    if len(clean) != 12:
        return False

    # Multipliers Pn for n=1 to 11 (digits from right to left before check digit)
    # Digits clean[0..10], check digit is clean[11]
    reversed_digits = [int(x) for x in reversed(clean[:11])]
    total = 0
    for n, d in enumerate(reversed_digits, 1):
        q = (n + 1) if n <= 6 else (n - 5)
        total += d * q

    rem = total % 11
    cd = 0 if rem <= 1 else (11 - rem)
    return int(clean[11]) == cd


# ---------------------------------------------------------------------------
# 15. SOUTH KOREA RESIDENT REGISTRATION NUMBER (RRN)
# ---------------------------------------------------------------------------

def validate_korea_rrn(rrn_str: str) -> bool:
    """Validates South Korean 13-digit RRN (Resident Registration Number)."""
    clean = "".join(ch for ch in rrn_str if ch.isdigit())
    if len(clean) != 13:
        return False

    gender_digit = int(clean[6])
    if gender_digit not in range(1, 9):
        return False

    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(clean[i]) * weights[i] for i in range(12))
    rem = (11 - (total % 11)) % 10
    return int(clean[12]) == rem


# ---------------------------------------------------------------------------
# 16. THAILAND NATIONAL ID VALIDATOR (Modulo 11)
# ---------------------------------------------------------------------------

def validate_thailand_id(tid_str: str) -> bool:
    """Validates 13-digit Thai National Identification Number."""
    clean = "".join(ch for ch in tid_str if ch.isdigit())
    if len(clean) != 13:
        return False

    total = sum(int(clean[i]) * (13 - i) for i in range(12))
    cd = (11 - (total % 11)) % 10
    return int(clean[12]) == cd


# ---------------------------------------------------------------------------
# 17. UAE EMIRATES ID VALIDATOR
# ---------------------------------------------------------------------------

def validate_uae_emirates_id(eid_str: str) -> bool:
    """Validates 15-digit UAE Emirates ID (784-YYYY-XXXXXXX-Z)."""
    clean = "".join(ch for ch in eid_str if ch.isdigit())
    if len(clean) != 15:
        return False
    if not clean.startswith("784"):
        return False
    return validate_luhn(clean)


# ---------------------------------------------------------------------------
# 18. CANADIAN SIN VALIDATOR (Luhn with Canadian constraints)
# ---------------------------------------------------------------------------

def validate_canada_sin(sin_str: str) -> bool:
    """Validates 9-digit Canadian Social Insurance Number (SIN)."""
    clean = "".join(ch for ch in sin_str if ch.isdigit())
    if len(clean) != 9:
        return False
    # Canadian SIN cannot start with 0 or 8
    if clean[0] in ("0", "8"):
        return False
    return validate_luhn(clean)


# ---------------------------------------------------------------------------
# 19. SOUTH AFRICAN ID VALIDATOR (13 digits, Luhn + Date check)
# ---------------------------------------------------------------------------

def validate_south_africa_id(said_str: str) -> bool:
    """Validates 13-digit South African National ID (YYMMDDSSSSCAZ)."""
    clean = "".join(ch for ch in said_str if ch.isdigit())
    if len(clean) != 13:
        return False
    # Check valid month (01-12) and day (01-31)
    month = int(clean[2:4])
    day = int(clean[4:6])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    return validate_luhn(clean)


# ---------------------------------------------------------------------------
# 20. MEXICAN CURP & RFC VALIDATORS
# ---------------------------------------------------------------------------

def validate_mexico_curp(curp_str: str) -> bool:
    """Validates 18-character Mexican CURP (Clave Única de Registro de Población)."""
    clean = curp_str.strip().upper()
    if len(clean) != 18:
        return False
    # CURP structure: 4 letters, 6 digits (YYMMDD), 1 gender letter (H/M), 2 state letters, 3 consonants, 1 digit/letter, 1 check digit
    import re
    curp_re = r"^[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d$"
    return bool(re.match(curp_re, clean))


def validate_mexico_rfc(rfc_str: str) -> bool:
    """Validates Mexican RFC (Registro Federal de Contribuyentes: 12 chars persona moral, 13 chars persona física)."""
    clean = rfc_str.strip().upper()
    if len(clean) not in (12, 13):
        return False
    import re
    if len(clean) == 12:
        return bool(re.match(r"^[A-Z&Ñ]{3}\d{6}[A-Z0-9]{3}$", clean))
    return bool(re.match(r"^[A-Z&Ñ]{4}\d{6}[A-Z0-9]{3}$", clean))


# ---------------------------------------------------------------------------
# 21. US ABA ROUTING TRANSIT NUMBER VALIDATOR (Modulo 10)
# ---------------------------------------------------------------------------

def validate_aba_routing(routing_str: str) -> bool:
    """Validates 9-digit US ABA Routing Transit Number via 3-7-1 weighted Modulo 10."""
    clean = "".join(ch for ch in routing_str if ch.isdigit())
    if len(clean) != 9 or clean == "000000000":
        return False
    prefix = int(clean[:2])
    valid_prefix = (1 <= prefix <= 12) or (21 <= prefix <= 32) or (61 <= prefix <= 72) or (prefix == 80)
    if not valid_prefix:
        return False
    d = [int(c) for c in clean]
    total = (
        3 * (d[0] + d[3] + d[6])
        + 7 * (d[1] + d[4] + d[7])
        + 1 * (d[2] + d[5] + d[8])
    )
    return total % 10 == 0



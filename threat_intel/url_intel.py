"""
URL/Domain Intelligence - foydalanuvchi chuqur arxitektura tahlilidagi
③-band.

Bu modul TARMOQQA CHIQMAYDI (hech qanday tashqi HTTP so'rov yubormaydi) -
faqat allaqachon ma'lum bo'lgan URL/domen matnini local, deterministik
tahlil qiladi:

  1. `normalize_url()` - URL'ni kanonik shaklga keltiradi (kichik harf,
     standart port olib tashlanadi, % kodlash ochiladi) - shunda
     `http://EXAMPLE.com:80/` va `http://example.com/` bir xil
     ko'rinadi.
  2. `has_userinfo_trick()` - `https://google.com@evil.com/login` kabi
     "ko'zga ishonchli, aslida boshqa domenga ulanadigan" URL'larni
     aniqlaydi (`@` belgisidan OLDINGI qism shunchaki foydalanuvchi
     nomi - brauzer/server buni e'tiborsiz qoldiradi, aslida `evil.com`ga
     ulanadi).
  3. `is_punycode()` - IDN xakerlik (`xn--...`) domenlarini aniqlaydi -
     bular ko'pincha ko'zga tanish brendga o'xshab ko'rinadigan, lekin
     texnik jihatdan butunlay boshqa domen.
  4. `domain_matches_blacklist()` - domen ierarxiyasi bo'yicha moslik
     (`cdn.login.evil.com` -> `evil.com` blacklist yozuviga mos keladi),
     lekin ODDIY STRING SUFFIX (`endswith()`) EMAS - bu xavfli, chunki
     `"notevil.com".endswith("evil.com")` ham `True` bo'ladi! Bu yerda
     domen LABEL (nuqta bilan ajratilgan qism) chegaralari bo'yicha
     solishtiriladi.
  5. `lexical_risk_score()` - fishing uchun xos so'zlar/naqshlar
     asosida 0-100 xavf balli (domenning o'zi hali hech qanday
     threat-intel bazasida bo'lmasa ham, "bu domen shubhali ko'rinadi"
     signalini beradi).

ATAYLAB BU BOSQICHDA QILINMAGAN (halol cheklov, keyingi bosqichlar
uchun qoldirilgan):
  - Redirect zanjiri tahlili - HAQIQIY HTTP so'rov talab qiladi, bu
    asosiy serverning o'zida EMAS, alohida izolyatsiya qilingan
    worker/sandbox'da bajarilishi kerak (xavfsizlik nuqtai nazaridan -
    noma'lum URL'ga to'g'ridan-to'g'ri so'rov yuborish o'zi xavf).
  - IP/ASN/domen reputatsiyasi (URLhaus/OTX/ThreatFox kabi tashqi
    threat-intel manbalar) - alohida integratsiya talab qiladi.
  - To'liq Public Suffix List (PSL) - `domain_matches_blacklist()`
    oddiy, universal qoidadan foydalanadi (pastga qarang) - "co.uk"
    kabi ko'p-segmentli davlat domenlarining har birini alohida
    hisobga OLMAYDI.
"""
import re
from urllib.parse import unquote, urlsplit

# Fishing sahifalarida tez-tez uchraydigan so'zlar (o'zi yetarli emas -
# faqat lexical_risk_score()ning bir komponenti).
PHISHING_KEYWORDS = {
    "login", "verify", "secure", "account", "password", "wallet",
    "update", "confirm", "signin", "banking", "security", "suspend",
    "authenticate", "recover", "unlock", "billing",
}

# Ko'p qalbakilashtiriladigan brendlar - domen nomida ular ORIGINAL
# domendan tashqarida uchrasa (masalan "microsoft-login-security.xyz"),
# bu kuchli shubha signali.
BRAND_KEYWORDS = {
    "microsoft", "office365", "google", "paypal", "apple", "amazon",
    "facebook", "instagram", "netflix", "bank", "gmail", "outlook",
    "whatsapp", "telegram",
}

# Brend so'zi domenning O'ZIDA (ushbu ro'yxatdagi haqiqiy domenlar)
# bo'lsa, bu soxta-pozitiv emas - haqiqiy Microsoft/Google va h.k.
_LEGITIMATE_BRAND_DOMAINS = {
    "microsoft.com", "office.com", "office365.com", "google.com",
    "paypal.com", "apple.com", "amazon.com", "facebook.com",
    "instagram.com", "netflix.com", "gmail.com", "outlook.com",
    "whatsapp.com", "telegram.org",
}


def normalize_url(raw_url: str) -> str:
    """
    URL'ni kanonik shaklga keltiradi:
      - sxema va host kichik harfga
      - standart port (http:80, https:443) olib tashlanadi
      - % kodlash ochiladi (masalan %2E -> .) - tahlil uchun, HECH
        QACHON so'rov yuborish uchun EMAS
      - oxiridagi "/" (agar path bo'sh bo'lsa) izchil qilinadi

    Agar `raw_url` sxemasiz (faqat domen) bo'lsa, o'zgarishsiz (faqat
    kichik harfga o'tkazilgan) qaytariladi.
    """
    if not raw_url:
        return raw_url
    raw_url = raw_url.strip()
    if "://" not in raw_url:
        return raw_url.lower()

    try:
        parts = urlsplit(raw_url)
    except ValueError:
        return raw_url.lower()

    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    default_port = {"http": 80, "https": 443}.get(scheme)
    netloc = host
    if port and port != default_port:
        netloc = f"{host}:{port}"

    path = unquote(parts.path or "")
    if not path:
        path = "/"

    normalized = f"{scheme}://{netloc}{path}"
    if parts.query:
        normalized += f"?{unquote(parts.query)}"
    return normalized


def has_userinfo_trick(raw_url: str) -> bool:
    """
    `https://google.com@evil.com/login` kabi URL'larni aniqlaydi -
    `@`dan OLDINGI qism HTTP standartiga ko'ra shunchaki "userinfo"
    (login/parol maydoni), brauzer buni domen sifatida TALQIN
    QILMAYDI - aslida `evil.com`ga ulanadi. Bu klassik fishing/
    ijtimoiy muhandislik texnikasi (ko'zga ishonchli domenga o'xshab
    ko'rinadi).
    """
    if not raw_url or "://" not in raw_url:
        return False
    try:
        parts = urlsplit(raw_url)
    except ValueError:
        return False
    # urlsplit() `userinfo@host` qismini avtomatik ajratadi -
    # `parts.username`/`parts.password` mavjudligi aynan shu holatni
    # anglatadi.
    return bool(parts.username)


def is_punycode(host: str) -> bool:
    """
    IDN (Internationalized Domain Name) xakerlik - `xn--` prefiksli
    har qanday label (masalan `xn--pypal-4ve.com` - ko'zga "paypal"ga
    o'xshab ko'rinishi mumkin bo'lgan, lekin texnik jihatdan BUTUNLAY
    BOSHQA belgi (masalan kirill 'а') ishlatilgan domen).
    """
    if not host:
        return False
    return any(label.lower().startswith("xn--") for label in host.split("."))


def extract_domain(raw_url_or_host: str) -> str:
    """URL yoki xom domen qatoridan hostname'ni ajratib oladi (kichik harfda)."""
    if not raw_url_or_host:
        return ""
    value = raw_url_or_host.strip()
    if "://" in value:
        try:
            host = urlsplit(value).hostname
        except ValueError:
            host = None
        return (host or "").lower().rstrip(".")
    # Sxemasiz - "domen:port/path" yoki xom domen bo'lishi mumkin
    value = value.split("/", 1)[0]
    value = value.rsplit("@", 1)[-1]  # userinfo@ bo'lsa, domen qismini olamiz
    value = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    return value.lower().rstrip(".")


def domain_parent_candidates(domain: str) -> list:
    """
    "cdn.login.evil.com" -> ["cdn.login.evil.com", "login.evil.com", "evil.com"]

    MUHIM: bu LABEL (nuqta bilan ajratilgan segment) chegaralari
    bo'yicha ishlaydi - oddiy `endswith()` EMAS. `endswith()` xavfli,
    chunki `"notevil.com".endswith("evil.com")` ham `True` bo'lardi
    (segment chegarasini hurmat qilmaydi). Bitta segmentli qoldiq
    (masalan yakuniy "com") ATAYLAB chiqarib tashlanadi - to'liq
    Public Suffix List bu yerda ishlatilmagani uchun, butun TLD'ni
    "blacklist mosligi" deb hisoblash xavfli/mantiqsiz bo'lardi.
    """
    domain = (domain or "").lower().rstrip(".")
    if not domain:
        return []
    labels = domain.split(".")
    if len(labels) < 2:
        return [domain] if domain else []
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def domain_matches_blacklist(domain: str, blacklist_domain: str) -> bool:
    """`domain` `blacklist_domain`ning o'zi yoki uning subdomeni bo'lsa `True`."""
    domain = (domain or "").lower().rstrip(".")
    blacklist_domain = (blacklist_domain or "").lower().rstrip(".")
    if not domain or not blacklist_domain:
        return False
    return domain == blacklist_domain or domain.endswith("." + blacklist_domain)


def lexical_risk_score(domain: str) -> dict:
    """
    Domen nomining o'zidan (hech qanday threat-intel bazasiga
    so'rovsiz) 0-100 fishing-uslubidagi xavf ballini hisoblaydi.

    MUHIM (halol): bu FAQAT leksik (so'z-asosli) evristika - haqiqiy
    threat-intel tasdiqlash EMAS. Yolg'on-pozitiv (masalan haqiqiy
    "secure-login.mycompany.uz" kabi ichki korporativ domen) mumkin -
    shuning uchun chaqiruvchi (`engine/parser_engine.py`) bu ballni
    FAQAT eng yuqori ("malicious", >=71) darajada avtomatik Alert
    yaratish uchun ishlatadi, pastroq darajalar hisoblanadi, lekin
    o'zi alert yaratmaydi (soxta-pozitiv xavfini cheklash uchun).

    Qaytaradi: {"score": int, "level": str, "reasons": [str, ...]}
    """
    reasons = []
    score = 0
    domain = (domain or "").lower().rstrip(".")

    if not domain:
        return {"score": 0, "level": "normal", "reasons": []}

    if is_punycode(domain):
        score += 45
        reasons.append("Punycode/IDN domen (xn--...) - ko'zga boshqa brendga o'xshab ko'rinishi mumkin")

    labels = domain.split(".")
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else domain

    brand_hit = None
    for brand in BRAND_KEYWORDS:
        if brand in domain and registrable not in _LEGITIMATE_BRAND_DOMAINS:
            brand_hit = brand
            break
    if brand_hit:
        score += 35
        reasons.append(f"Brend nomi ('{brand_hit}') domenning o'zida, lekin bu rasmiy domen EMAS")

    keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in domain]
    if keyword_hits:
        score += min(30, 10 * len(keyword_hits))
        reasons.append(f"Fishing'ga xos so'z(lar): {', '.join(sorted(keyword_hits)[:5])}")

    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        score += 15
        reasons.append(f"Ko'p chiziqcha ({hyphen_count} ta) - odatiy domenlarda kam uchraydi")
    elif hyphen_count >= 2:
        score += 8

    digit_count = sum(c.isdigit() for c in domain)
    if digit_count >= 4:
        score += 10
        reasons.append(f"Ko'p raqam ({digit_count} ta)")

    if len(labels) >= 5:
        score += 10
        reasons.append(f"G'ayrioddiy chuqur subdomen ({len(labels)} segment)")

    suspicious_tlds = {"xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf"}
    if labels and labels[-1] in suspicious_tlds:
        score += 15
        reasons.append(f"Shubha uyg'otadigan TLD (.{labels[-1]})")

    score = min(100, score)
    if score >= 71:
        level = "malicious"
    elif score >= 41:
        level = "high"
    elif score >= 21:
        level = "suspicious"
    else:
        level = "normal"

    return {"score": score, "level": level, "reasons": reasons}


def analyze_url(raw_url_or_domain: str) -> dict:
    """
    Orchestrator - yuqoridagi barcha tekshiruvlarni birlashtirib,
    bitta natija qaytaradi. `dashboard`/`engine` uchun qulay yagona
    kirish nuqtasi.
    """
    domain = extract_domain(raw_url_or_domain)
    normalized = normalize_url(raw_url_or_domain) if "://" in (raw_url_or_domain or "") else raw_url_or_domain
    userinfo_trick = has_userinfo_trick(raw_url_or_domain)
    punycode = is_punycode(domain)
    lexical = lexical_risk_score(domain)

    reasons = list(lexical["reasons"])
    score = lexical["score"]
    if userinfo_trick:
        score = min(100, score + 40)
        reasons.append("URL'da '@' (userinfo) tuzog'i - ko'rinadigan domen bilan HAQIQIY ulanish domeni FARQLI")

    level = lexical["level"]
    if score >= 71:
        level = "malicious"
    elif score >= 41:
        level = "high"
    elif score >= 21:
        level = "suspicious"

    return {
        "domain": domain,
        "normalized_url": normalized,
        "is_punycode": punycode,
        "has_userinfo_trick": userinfo_trick,
        "score": score,
        "level": level,
        "reasons": reasons,
    }

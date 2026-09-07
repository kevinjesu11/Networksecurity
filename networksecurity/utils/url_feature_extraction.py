import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

try:
    import whois
except ImportError:
    whois = None

from networksecurity.logging.logger import logging
from networksecurity.utils.safe_fetch import (
    BlockedURLError,
    GENERIC_FETCH_ERROR,
    safe_get,
)

# Ordered to match data_schema/schema.yaml minus the TARGET_COLUMN ("Result"),
# which is the column order the trained preprocessor/model expect. The 5 original
# dataset columns with no live/free data source anymore (Alexa traffic rank, Google
# PageRank API, Google index/backlink counts, phishing blacklist reports) are
# dropped at ingestion (see LEGACY_FEATURE_COLUMNS_TO_DROP) and the model is
# retrained without them, so this extractor only ever computes live-derivable
# features instead of guessing at dead ones.
FEATURE_ORDER = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord",
]

_SHORTENING_SERVICES = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|"
    r"cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|"
    r"snipurl\.com|short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snipr\.com|"
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|u\.to|j\.mp|buzurl\.com|cutt\.us|"
    r"u\.bb|yourls\.org|v\.gd|link\.zip\.net",
    re.IGNORECASE,
)

_REQUEST_TIMEOUT_SECONDS = 6.0
_REQUEST_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; PhishGuardBot/1.0)"}

# For most of these columns, the textbook description of the feature (1 = phishing
# indicator present) is the polarity implemented below. But measured against the
# actual training CSV (correlation of each raw column against Result), these
# specific columns run the opposite way in this dataset - e.g. URL_of_Anchor=1
# empirically correlates with legitimate sites, not phishing ones. Flipping them
# here makes the extractor's output match what the model actually learned instead
# of what the original paper describes.
_FLIP_POLARITY = {
    "having_IP_Address", "having_Sub_Domain", "Prefix_Suffix", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "port",
    "on_mouseover", "RightClick", "age_of_domain", "DNSRecord", "having_At_Symbol",
}


class URLFeatureExtractor:
    """Best-effort, live re-implementation of the classic phishing-website feature
    set for a single URL. Network/whois lookups are wrapped individually so a single
    failure degrades one feature instead of the whole extraction."""

    def __init__(self, url: str, timeout: float = _REQUEST_TIMEOUT_SECONDS):
        url = url.strip()
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "http://" + url

        self.url = url
        self.timeout = timeout
        self.parsed = urlparse(self.url)
        self.hostname = (self.parsed.hostname or "").lower()
        self.domain = self.hostname[4:] if self.hostname.startswith("www.") else self.hostname

        self.response = None
        self.soup = None
        self.fetch_error = None
        self.blocked_reason = None
        try:
            # Validates the resolved address before every hop; see safe_fetch.
            self.response = safe_get(self.url, self.timeout, _REQUEST_HEADERS)
            self.soup = BeautifulSoup(self.response.text, "html.parser")
        except BlockedURLError as e:
            # Worth surfacing verbatim: the user chose this target, and being told
            # it points somewhere internal is the useful answer.
            self.blocked_reason = str(e)
            self.fetch_error = str(e)
            logging.info(f"URL feature extraction: blocked {self.url}: {e}")
        except Exception as e:
            # Deliberately generic. The exception text separates "refused" from
            # "timed out", which maps out internal hosts for whoever submitted it.
            self.fetch_error = GENERIC_FETCH_ERROR
            logging.info(f"URL feature extraction: could not fetch {self.url}: {e}")

        self.whois_record = None
        if whois is not None and self.domain:
            try:
                self.whois_record = whois.whois(self.domain)
            except Exception as e:
                logging.info(f"URL feature extraction: whois lookup failed for {self.domain}: {e}")

    # -- helpers --------------------------------------------------------

    def _is_ip_literal(self) -> bool:
        try:
            ipaddress.ip_address(self.hostname)
            return True
        except ValueError:
            return False

    @staticmethod
    def _first(value):
        if isinstance(value, list):
            return value[0] if value else None
        return value

    def _external_ratio(self, sources) -> int:
        sources = [s for s in sources if s]
        if not sources:
            return -1
        external = sum(1 for s in sources if s.startswith("http") and self.domain not in s)
        ratio = external / len(sources)
        if ratio < 0.22:
            return -1
        if ratio <= 0.61:
            return 0
        return 1

    # -- individual features --------------------------------------------

    def having_IP_Address(self) -> int:
        return 1 if self._is_ip_literal() else -1

    def URL_Length(self) -> int:
        length = len(self.url)
        if length < 54:
            return -1
        if length <= 75:
            return 0
        return 1

    def Shortining_Service(self) -> int:
        return 1 if _SHORTENING_SERVICES.search(self.url) else -1

    def having_At_Symbol(self) -> int:
        return 1 if "@" in self.url else -1

    def double_slash_redirecting(self) -> int:
        return 1 if self.url.rfind("//") > 7 else -1

    def Prefix_Suffix(self) -> int:
        return 1 if "-" in self.domain else -1

    def having_Sub_Domain(self) -> int:
        dots = self.domain.count(".")
        if dots <= 1:
            return -1
        if dots == 2:
            return 0
        return 1

    def SSLfinal_State(self) -> int:
        if self.parsed.scheme != "https" or self._is_ip_literal():
            return -1
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            return 1 if not_after > datetime.utcnow() else 0
        except Exception:
            return 0

    def Domain_registeration_length(self) -> int:
        if self.whois_record is None:
            return -1
        try:
            created = self._first(self.whois_record.creation_date)
            expires = self._first(self.whois_record.expiration_date)
            if not created or not expires:
                return -1
            return 1 if (expires - created).days <= 365 else -1
        except Exception:
            return -1

    def Favicon(self) -> int:
        if self.soup is None:
            return 1
        icon = self.soup.find("link", rel=lambda v: v and "icon" in v.lower())
        if icon is None or not icon.get("href"):
            return -1
        href = icon["href"]
        return -1 if href.startswith("/") or self.domain in href else 1

    def port(self) -> int:
        return 1 if self.parsed.port and self.parsed.port not in (80, 443) else -1

    def HTTPS_token(self) -> int:
        return 1 if "https" in self.hostname else -1

    def Request_URL(self) -> int:
        if self.soup is None:
            return 1
        sources = [t.get("src") for t in self.soup.find_all(["img", "script", "audio", "video", "iframe"])]
        return self._external_ratio(sources)

    def URL_of_Anchor(self) -> int:
        if self.soup is None:
            return 1
        anchors = self.soup.find_all("a", href=True)
        if not anchors:
            return -1
        bad = 0
        for a in anchors:
            href = a["href"].strip().lower()
            if href in ("", "#") or href.startswith("javascript:"):
                bad += 1
            elif href.startswith("http") and self.domain not in href:
                bad += 1
        ratio = bad / len(anchors)
        if ratio < 0.31:
            return -1
        if ratio <= 0.67:
            return 0
        return 1

    def Links_in_tags(self) -> int:
        if self.soup is None:
            return 1
        sources = []
        for tag in self.soup.find_all(["meta", "script", "link"]):
            sources.append(tag.get("content") or tag.get("src") or tag.get("href"))
        return self._external_ratio(sources)

    def SFH(self) -> int:
        if self.soup is None:
            return -1
        forms = self.soup.find_all("form")
        if not forms:
            return -1
        action = (forms[0].get("action") or "").strip().lower()
        if action in ("", "about:blank"):
            return 1
        if action.startswith("http") and self.domain not in action:
            return 0
        return -1

    def Submitting_to_email(self) -> int:
        if self.soup is None:
            return -1
        return 1 if "mailto:" in str(self.soup).lower() else -1

    def Abnormal_URL(self) -> int:
        if self.whois_record is None:
            return 1
        try:
            registered = self._first(self.whois_record.domain_name) or ""
            return -1 if registered.lower() in self.domain.lower() else 1
        except Exception:
            return 1

    def Redirect(self) -> int:
        count = len(self.response.history) if self.response is not None else 0
        if count <= 1:
            return -1
        if count <= 3:
            return 0
        return 1

    def on_mouseover(self) -> int:
        if self.soup is None:
            return -1
        html = str(self.soup).lower()
        return 1 if "onmouseover" in html and "window.status" in html else -1

    def RightClick(self) -> int:
        if self.soup is None:
            return -1
        html = str(self.soup).lower()
        return 1 if "event.button==2" in html or "contextmenu" in html else -1

    def popUpWidnow(self) -> int:
        if self.soup is None:
            return -1
        return 1 if re.search(r"alert\s*\(|window\.open\s*\(", str(self.soup).lower()) else -1

    def Iframe(self) -> int:
        if self.soup is None:
            return -1
        frames = self.soup.find_all(["iframe", "frame"])
        return 1 if frames else -1

    def age_of_domain(self) -> int:
        if self.whois_record is None:
            return -1
        try:
            created = self._first(self.whois_record.creation_date)
            if not created:
                return -1
            age_days = (datetime.utcnow() - created).days
            return -1 if age_days >= 180 else 1
        except Exception:
            return -1

    def DNSRecord(self) -> int:
        try:
            socket.gethostbyname(self.hostname)
            return -1
        except Exception:
            return 1

    # -- driver -----------------------------------------------------------

    def extract(self) -> dict:
        live_extractors = {
            "having_IP_Address": self.having_IP_Address,
            "URL_Length": self.URL_Length,
            "Shortining_Service": self.Shortining_Service,
            "having_At_Symbol": self.having_At_Symbol,
            "double_slash_redirecting": self.double_slash_redirecting,
            "Prefix_Suffix": self.Prefix_Suffix,
            "having_Sub_Domain": self.having_Sub_Domain,
            "SSLfinal_State": self.SSLfinal_State,
            "Domain_registeration_length": self.Domain_registeration_length,
            "Favicon": self.Favicon,
            "port": self.port,
            "HTTPS_token": self.HTTPS_token,
            "Request_URL": self.Request_URL,
            "URL_of_Anchor": self.URL_of_Anchor,
            "Links_in_tags": self.Links_in_tags,
            "SFH": self.SFH,
            "Submitting_to_email": self.Submitting_to_email,
            "Abnormal_URL": self.Abnormal_URL,
            "Redirect": self.Redirect,
            "on_mouseover": self.on_mouseover,
            "RightClick": self.RightClick,
            "popUpWidnow": self.popUpWidnow,
            "Iframe": self.Iframe,
            "age_of_domain": self.age_of_domain,
            "DNSRecord": self.DNSRecord,
        }

        features = {}
        for name, fn in live_extractors.items():
            try:
                value = fn()
            except Exception as e:
                logging.info(f"URL feature extraction: {name} failed for {self.url}: {e}")
                value = -1
            if name in _FLIP_POLARITY:
                value = -value
            features[name] = value

        return {col: features[col] for col in FEATURE_ORDER}


def extract_url_features(url: str, timeout: float = _REQUEST_TIMEOUT_SECONDS):
    """Returns (features_dict, meta_dict) for a single URL, ready to feed straight
    into the trained preprocessor/model as a one-row DataFrame."""
    extractor = URLFeatureExtractor(url, timeout=timeout)
    features = extractor.extract()
    meta = {
        "resolved_url": extractor.url,
        "fetch_error": extractor.fetch_error,
        "blocked_reason": extractor.blocked_reason,
        "whois_available": extractor.whois_record is not None,
    }
    return features, meta

import logging
import re
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger("ai_firewall.phishing_detector")

MAX_TEXT_LENGTH = 50000
MAX_URL_LENGTH = 4096


class PhishingDetector:

    # Urgency and manipulation language patterns
    URGENCY_PATTERNS = [
        r'\b(urgent|immediately|act now|limited time|expires|deadline|last chance)\b',
        r'\b(verify your account|confirm your identity|update your information)\b',
        r'\b(suspended|disabled|restricted|blocked|terminated)\b',
        r'\b(click here|click below|click this link|follow this link)\b',
        r'\b(free|winner|won|prize|reward|gift|congratulations)\b',
        r'\b(bank|paypal|amazon|netflix|microsoft|apple|google|irs|fbi)\b.*\b(account|verify|login|secure)\b',
    ]

    # Suspicious URL patterns
    SUSPICIOUS_URL_PATTERNS = [
        r'@',  # URLs with @ sign
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # Raw IP in URL
        r'(?:bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd)',  # URL shorteners
        r'(?:login|secure|verify|account|update|confirm).*(?:\.ru|\.cn|\.tk|\.ml|\.ga|\.cf)',
        r'[a-z0-9]{20,}\.',  # Very long random subdomain
        r'(?:paypal|amazon|google|microsoft|apple|facebook|netflix)(?:[^.]*\.(?!com|net|org))',  # Brand typosquatting
    ]

    # Known malicious TLDs with high phishing rates
    SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click', '.download'}

    # Trusted domains whitelist
    TRUSTED_DOMAINS = {
        'google.com', 'gmail.com', 'microsoft.com', 'outlook.com',
        'amazon.com', 'apple.com', 'paypal.com', 'facebook.com',
        'twitter.com', 'linkedin.com', 'github.com', 'youtube.com'
    }

    def analyze_text(self, text: str) -> dict:
        """Analyze message text for phishing indicators with length safety and error boundaries."""
        default_result = {
            'score': 0,
            'is_phishing': False,
            'risk_level': 'LOW',
            'indicators': [],
            'urls_found': [],
            'analyzed_at': datetime.now().isoformat(),
        }

        if not text or not isinstance(text, str):
            return default_result

        try:
            score = 0
            indicators = []

            # Enforce input length limit
            if len(text) > MAX_TEXT_LENGTH:
                text = text[:MAX_TEXT_LENGTH]
                indicators.append(f"Input text exceeded {MAX_TEXT_LENGTH} characters and was truncated.")

            text_lower = text.lower()

            # Check urgency patterns
            for pattern in self.URGENCY_PATTERNS:
                matches = re.findall(pattern, text_lower, re.IGNORECASE)
                if matches:
                    score += 15
                    match_str = matches[0] if isinstance(matches[0], str) else matches[0][0]
                    indicators.append(f"Urgency language detected: {match_str}")

            # Check for URLs in text
            urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
            for url in urls[:15]:  # limit URL inspections
                url_result = self.analyze_url(url)
                score += url_result.get('score', 0)
                indicators.extend(url_result.get('indicators', []))

            # Check for suspicious email patterns
            if re.search(r'[\w.-]+@[\w.-]+\.\w+', text):
                email_domains = re.findall(r'@([\w.-]+\.\w+)', text)
                for domain in email_domains[:10]:
                    if any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
                        score += 20
                        indicators.append(f"Suspicious email domain: {domain}")

            # Excessive capitalization (SHOUT SPAM pattern)
            words = text.split()
            if len(words) > 5:
                caps_ratio = sum(1 for w in words if w.isupper() and len(w) > 2) / len(words)
                if caps_ratio > 0.3:
                    score += 10
                    indicators.append("Excessive capitalization detected")

            # Check for HTML in plain message context
            if re.search(r'<(?:a|img|script|iframe)[^>]*>', text, re.IGNORECASE):
                score += 25
                indicators.append("Embedded HTML links or scripts detected")

            score = min(score, 100)
            return {
                'score': score,
                'is_phishing': score >= 50,
                'risk_level': (
                    'CRITICAL' if score >= 75 else 'HIGH' if score >= 50 else 'MEDIUM' if score >= 25 else 'LOW'
                ),
                'indicators': indicators,
                'urls_found': urls[:15],
                'analyzed_at': datetime.now().isoformat(),
            }
        except Exception as exc:
            logger.warning(f"Error analyzing phishing text, using safe fallback: {exc}")
            return {
                **default_result,
                'indicators': [f"Analysis fallback due to error: {str(exc)}"],
            }

    def analyze_url(self, url: str) -> dict:
        """Deep analysis of a single URL with length safety and error boundaries."""
        default_result = {
            'score': 0,
            'url': url if isinstance(url, str) else "",
            'is_phishing': False,
            'risk_level': 'LOW',
            'indicators': [],
            'analyzed_at': datetime.now().isoformat(),
        }

        if not url or not isinstance(url, str):
            return default_result

        try:
            if len(url) > MAX_URL_LENGTH:
                url = url[:MAX_URL_LENGTH]

            score = 0
            indicators = []

            parsed = urlparse(url)
            domain = (parsed.netloc or "").lower()
            path = (parsed.path or "").lower()
            full_url = url.lower()

            # Check if trusted domain
            base_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
            if base_domain in self.TRUSTED_DOMAINS or domain in self.TRUSTED_DOMAINS:
                return {
                    'score': 0,
                    'url': url,
                    'is_phishing': False,
                    'risk_level': 'LOW',
                    'indicators': ['Trusted domain'],
                    'analyzed_at': datetime.now().isoformat(),
                }

            # Check suspicious patterns
            for pattern in self.SUSPICIOUS_URL_PATTERNS:
                if re.search(pattern, full_url, re.IGNORECASE):
                    score += 20
                    indicators.append(f"Suspicious URL pattern: {pattern[:30]}")

            # Check suspicious TLD
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    score += 25
                    indicators.append(f"High-risk TLD: {tld}")

            # Check for brand impersonation
            brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix', 'bank']
            for brand in brands:
                if brand in domain and base_domain not in self.TRUSTED_DOMAINS and domain not in self.TRUSTED_DOMAINS:
                    score += 30
                    indicators.append(f"Possible brand impersonation: {brand}")
                    break

            # Check for suspicious path keywords
            suspicious_paths = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm', 'password']
            for sp in suspicious_paths:
                if sp in path:
                    score += 10
                    indicators.append(f"Suspicious path keyword: {sp}")
                    break

            # Check HTTP vs HTTPS
            if parsed.scheme == 'http':
                score += 15
                indicators.append("Non-HTTPS connection (no encryption)")

            # Check URL length (phishing URLs are often very long)
            if len(url) > 100:
                score += 10
                indicators.append(f"Unusually long URL ({len(url)} chars)")

            score = min(score, 100)
            return {
                'score': score,
                'url': url,
                'is_phishing': score >= 50,
                'risk_level': (
                    'CRITICAL' if score >= 75 else 'HIGH' if score >= 50 else 'MEDIUM' if score >= 25 else 'LOW'
                ),
                'indicators': indicators,
                'analyzed_at': datetime.now().isoformat(),
            }
        except Exception as exc:
            logger.warning(f"Error analyzing phishing URL: {exc}")
            return {
                **default_result,
                'indicators': [f"URL analysis fallback due to error: {str(exc)}"],
            }


detector = PhishingDetector()

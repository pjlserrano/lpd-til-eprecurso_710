import ssl
import urllib.parse
import urllib.request


def _fetch(url: str, timeout: int = 8):
    context = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "LPD-Lab-Checker/1.0"})
    return urllib.request.urlopen(req, timeout=timeout, context=context)


def check_url(url: str) -> dict:
    findings: list[str] = []
    score = 0

    try:
        response = _fetch(url)
    except Exception as exc:
        return {"url": url, "score": 0, "findings": [f"Erro ao ligar ao URL: {exc}"]}

    headers = {k.lower(): v for k, v in response.headers.items()}

    if url.startswith("https://"):
        score += 1
    else:
        findings.append("Nao usa HTTPS por defeito.")

    if "strict-transport-security" in headers:
        score += 1
    else:
        findings.append("Sem HSTS (Strict-Transport-Security).")

    if "x-frame-options" in headers or "frame-ancestors" in headers.get("content-security-policy", "").lower():
        score += 1
    else:
        findings.append("Possivel Clickjacking (falta X-Frame-Options/CSP frame-ancestors).")

    if headers.get("x-content-type-options", "").lower() == "nosniff":
        score += 1
    else:
        findings.append("Sem protecao MIME sniffing (X-Content-Type-Options: nosniff).")

    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server:
        findings.append(f"Banner de servidor exposto: {server}")
    if powered:
        findings.append(f"Versao de tecnologia exposta: {powered}")

    xss_probe = "<script>alert(1)</script>"
    parsed = urllib.parse.urlparse(url)
    probe_url = urllib.parse.urlunparse(
        parsed._replace(query=f"q={urllib.parse.quote_plus(xss_probe)}")
    )

    try:
        body = _fetch(probe_url).read(200000).decode("utf-8", errors="ignore")
        if xss_probe in body:
            findings.append("Possivel XSS refletido (payload apareceu na resposta).")
        else:
            score += 1
    except Exception:
        findings.append("Nao foi possivel testar XSS refletido.")

    return {"url": url, "score": score, "findings": findings}


def run_web_check() -> None:
    url = input("URL a verificar (ex: http://192.168.30.10): ").strip()
    if not url:
        print("URL invalido.")
        return

    result = check_url(url)
    print(f"\nURL: {result['url']}")
    print(f"Score basico: {result['score']}/5")
    print("Achados:")
    for item in result["findings"]:
        print(f"- {item}")

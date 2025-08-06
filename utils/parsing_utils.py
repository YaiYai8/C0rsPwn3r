from typing import List, Dict, Optional, Tuple

def analyze_origin_behavior(results: List[dict], endpoint: str) -> List[dict]:
    """
    Analyze a list of CORS responses for different Origins to detect vulnerabilities.

    :param results: List of dicts, each containing origin, status, headers, and body.
    :param endpoint: The endpoint being tested (used for reporting).
    :return: List of findings (each a dict with vuln name, evidence, and endpoint).
    """
    findings = []
    findings.extend(check_blind_subdomain_trust(results, endpoint))
    findings.extend(check_parser_confusion(results, endpoint))
    findings.extend(check_null_origin(results, endpoint))
    findings.extend(check_wildcard_plus_credentials(results, endpoint))
    findings.extend(check_reflected_origin(results, endpoint))   
    return findings

def check_blind_subdomain_trust(results: List[dict], endpoint: str) -> List[dict]:
    """
    Detects if the server accepts non-existent subdomains under its own domain (blind trust).
    
    :param results: List of response dictionaries from all tested origins
    :param endpoint: The endpoint being tested
    :return: List of findings for this specific issue
    """
    findings = []
    for r in results:
        origin = r["origin"]
        acao = r["headers"].get("Access-Control-Allow-Origin", "")
        acac = r["headers"].get("Access-Control-Allow-Credentials", "")

        # Check only for the crafted subdomain we used
        if "YshachaR." in origin and origin == acao and acac.lower() == "true":
            findings.append({
                "vuln": "Blind Subdomain Trust",
                "info": "The server accepts origins from subdomains that may not actually exist or be controlled.\n  This can lead to CORS exploitation if the attacker is able to register such subdomains or use DNS rebinding techniques.",
                "evidence": {
                    "origin": origin,
                    "acao": acao,
                    "acac": acac
                },
                "endpoint": endpoint
            })
    return findings

def check_parser_confusion(results: List[dict], endpoint: str) -> List[dict]:
    """
    Detects improper origin whitelist matching via parser confusion or prefix/suffix tricks.    
    If such an origin is reflected in ACAO and ACAC is true, it's a misconfiguration.
    :param results: List of response dictionaries from all tested origins
    :param endpoint: The endpoint being tested
    :return: List of findings for this specific issue
    """
    findings = []
    for r in results:
        origin = r["origin"]
        acao = r["headers"].get("Access-Control-Allow-Origin", "")
        acac = r["headers"].get("Access-Control-Allow-Credentials", "")
        
        # Match: the suspicious origin is reflected + credentials allowed
        if acao == origin and acac.lower() == "true":
            findings.append({
                "vuln": "Parser Confusion / Improper Origin Matching",
                "info": "The server reflected a crafted origin that looks similar to the real domain.\nThis suggests the origin whitelist uses loose string matching.\nSuch behavior may allow bypass via parser tricks (e.g. suffix, encoded dot, concatenation).",
                "evidence": {
                    "origin": origin,
                    "acao": acao,
                    "acac": acac
                },
                "endpoint": endpoint
            })
    return findings

def check_wildcard_plus_credentials(results: List[dict], endpoint: str) -> List[dict]:
    """
    Detects a critical CORS misconfiguration where the server responds with
    Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.
    :param results: List of response dictionaries from all tested origins
    :param endpoint: The endpoint being tested
    :return: List of findings for this specific issue
    """
    findings = []
    for r in results:
        acao = r["headers"].get("Access-Control-Allow-Origin", "")
        acac = r["headers"].get("Access-Control-Allow-Credentials", "")
        origin = r["origin"]
        if acao == '*' and acac.lower() == "true":
            findings.append({
                "vuln": "Wildcard (*) + Credentials",
                "info":"The server responds with Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true.\n This combination is forbidden by the CORS specification.\n It may allow unauthorized access to protected resources if enforced improperly by the client.",
                "evidence": {
                    "origin": origin,
                    "acao": acao,
                    "acac": acac
                },
                "endpoint": endpoint
            })
    return findings

def check_reflected_origin(results: List[dict], endpoint: str) -> List[dict]:
    """
    Detects Reflected Origin + Credentials misconfiguration.

    Condition: ACAO == Origin and ACAC == true

    :return: List of findings for this specific issue.
    """
    findings = []
    for r in results:
        acao = r["headers"].get("Access-Control-Allow-Origin", "")
        acac = r["headers"].get("Access-Control-Allow-Credentials", "")
        origin = r["origin"]
        if acao == origin and acac.lower() == "true":
            findings.append({
                "vuln": "Reflected Origin + Allow-Credentials true",
                "info": "The server reflects the Origin value in the ACAO header.\n This may indicate that arbitrary origins are allowed.\n If credentials are also allowed, it can enable cross-origin theft of sensitive data.",
                "evidence": {
                    "origin": origin,
                    "acao": acao,
                    "acac": acac
                },
                "endpoint": endpoint
            })
    return findings

def check_null_origin(results: List[dict], endpoint: str) -> List[dict]:
    """
    Detects if 'Access-Control-Allow-Origin: null' is accepted by the server.
    """
    findings = []
    for result in results:
        acao = result["headers"].get("Access-Control-Allow-Origin")
        acac = result["headers"].get("Access-Control-Allow-Credentials")
        origin = result["origin"]

        if acao == "null":
            findings.append({
                "vuln": "Null Origin Whitelist",
                "info": "The server responds with ACAO: null, indicating it accepts the null origin.\n This is risky when combined with credentialed requests.\n Null origins may occur in sandboxed iframes or certain file-based requests.",
                "evidence": {
                    "origin": origin,
                    "acao": acao,
                    "acac": acac
                },
                "endpoint": endpoint
            })
    return findings

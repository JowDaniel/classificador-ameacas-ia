"""
Módulo de utilitários para o Classificador de Ameaças com IA
Contém funções auxiliares para parsing, normalização e logging
"""

import re
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


def setup_logging(log_level: str = "INFO") -> None:
    """
    Configura o sistema de logging da aplicação
    
    Args:
        log_level: Nível de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('threat_classifier.log'),
            logging.StreamHandler()
        ]
    )


def normalize_text(text: str) -> str:
    """
    Normaliza texto removendo caracteres especiais e formatação desnecessária
    
    Args:
        text: Texto a ser normalizado
        
    Returns:
        Texto normalizado
    """
    if not text:
        return ""
    
    # Remove quebras de linha excessivas
    text = re.sub(r'\n+', '\n', text)
    
    # Remove espaços excessivos
    text = re.sub(r' +', ' ', text)
    
    # Remove caracteres de controle
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    
    return text.strip()


def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """
    Extrai IoCs básicos do texto usando regex
    
    Args:
        text: Texto para extrair IoCs
        
    Returns:
        Dicionário com IoCs categorizados
    """
    iocs = {
        "ips": [],
        "dominios": [],
        "urls": [],
        "hashes": [],
        "emails": []
    }
    
    # Regex para IPs
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    iocs["ips"] = list(set(re.findall(ip_pattern, text)))
    
    # Regex para domínios
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    potential_domains = re.findall(domain_pattern, text)
    # Filtra IPs que podem ter sido capturados como domínios
    iocs["dominios"] = [d for d in set(potential_domains) if not re.match(ip_pattern, d)]
    
    # Regex para URLs
    url_pattern = r'https?://[^\s<>"\'`|(){}[\]]*'
    iocs["urls"] = list(set(re.findall(url_pattern, text)))
    
    # Regex para hashes (MD5, SHA1, SHA256)
    hash_patterns = [
        r'\b[a-fA-F0-9]{32}\b',  # MD5
        r'\b[a-fA-F0-9]{40}\b',  # SHA1
        r'\b[a-fA-F0-9]{64}\b'   # SHA256
    ]
    for pattern in hash_patterns:
        iocs["hashes"].extend(re.findall(pattern, text))
    iocs["hashes"] = list(set(iocs["hashes"]))
    
    # Regex para emails
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    iocs["emails"] = list(set(re.findall(email_pattern, text)))
    
    return iocs


def validate_json_structure(data: Dict[str, Any]) -> bool:
    """
    Valida se a estrutura JSON está conforme o esperado
    
    Args:
        data: Dicionário a ser validado
        
    Returns:
        True se válido, False caso contrário
    """
    required_fields = ["iocs", "tipo_ameaca", "mitre", "fonte", "data_analise"]
    
    return all(field in data for field in required_fields)


def sanitize_filename(filename: str) -> str:
    """
    Sanitiza nome de arquivo removendo caracteres inválidos
    
    Args:
        filename: Nome do arquivo
        
    Returns:
        Nome do arquivo sanitizado
    """
    # Remove caracteres inválidos para nomes de arquivo
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Limita o tamanho
    return filename[:255] if len(filename) > 255 else filename


def ensure_directory_exists(path: str) -> None:
    """
    Garante que um diretório existe, criando-o se necessário
    
    Args:
        path: Caminho do diretório
    """
    Path(path).mkdir(parents=True, exist_ok=True)


def load_json_file(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Carrega um arquivo JSON de forma segura
    
    Args:
        file_path: Caminho do arquivo JSON
        
    Returns:
        Dicionário com dados ou None se erro
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Erro ao carregar arquivo JSON {file_path}: {e}")
        return None


def save_json_file(data: Dict[str, Any], file_path: str) -> bool:
    """
    Salva dados em arquivo JSON de forma segura
    
    Args:
        data: Dados a serem salvos
        file_path: Caminho do arquivo
        
    Returns:
        True se sucesso, False caso contrário
    """
    try:
        ensure_directory_exists(str(Path(file_path).parent))
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logging.error(f"Erro ao salvar arquivo JSON {file_path}: {e}")
        return False


def get_timestamp() -> str:
    """
    Retorna timestamp atual formatado
    
    Returns:
        String com timestamp
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Dicionário com técnicas MITRE ATT&CK e seus nomes
MITRE_TECHNIQUES = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link", 
    "T1566.003": "Phishing: Spearphishing via Service",
    "T1486": "Data Encrypted for Impact",
    "T1027": "Obfuscated Files or Information",
    "T1078": "Valid Accounts",
    "T1134": "Access Token Manipulation",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1055": "Process Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1047": "Windows Management Instrumentation",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1136": "Create Account",
    "T1136.001": "Create Account: Local Account",
    "T1136.002": "Create Account: Domain Account",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    "T1087.001": "Account Discovery: Local Account",
    "T1087.002": "Account Discovery: Domain Account",
    "T1016": "System Network Configuration Discovery",
    "T1033": "System Owner/User Discovery",
    "T1049": "System Network Connections Discovery",
    "T1057": "Process Discovery",
    "T1518": "Software Discovery",
    "T1518.001": "Software Discovery: Security Software Discovery",
    "T1012": "Query Registry",
    "T1124": "System Time Discovery",
    "T1007": "System Service Discovery",
    "T1135": "Network Share Discovery",
    "T1046": "Network Service Scanning",
    "T1040": "Network Sniffing",
    "T1018": "Remote System Discovery",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1048.003": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
    "T1567": "Exfiltration Over Web Service",
    "T1567.002": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
    "T1005": "Data from Local System",
    "T1039": "Data from Network Shared Drive",
    "T1025": "Data from Removable Media",
    "T1074": "Data Staged",
    "T1074.001": "Data Staged: Local Data Staging",
    "T1074.002": "Data Staged: Remote Data Staging",
    "T1560": "Archive Collected Data",
    "T1560.001": "Archive Collected Data: Archive via Utility",
    "T1560.002": "Archive Collected Data: Archive via Library",
    "T1560.003": "Archive Collected Data: Archive via Custom Method",
    "T1119": "Automated Collection",
    "T1114": "Email Collection",
    "T1114.001": "Email Collection: Local Email Collection",
    "T1114.002": "Email Collection: Remote Email Collection",
    "T1114.003": "Email Collection: Email Forwarding Rule",
    "T1115": "Clipboard Data",
    "T1113": "Screen Capture",
    "T1125": "Video Capture",
    "T1123": "Audio Capture",
    "T1185": "Browser Session Hijacking",
    "T1539": "Steal Web Session Cookie",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1552.002": "Unsecured Credentials: Credentials in Registry",
    "T1552.003": "Unsecured Credentials: Bash History",
    "T1552.004": "Unsecured Credentials: Private Keys",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1552.006": "Unsecured Credentials: Group Policy Preferences",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.002": "Brute Force: Password Cracking",
    "T1110.003": "Brute Force: Password Spraying",
    "T1110.004": "Brute Force: Credential Stuffing",
    "T1212": "Exploitation for Credential Access",
    "T1187": "Forced Authentication",
    "T1606": "Forge Web Credentials",
    "T1606.001": "Forge Web Credentials: Web Cookies",
    "T1606.002": "Forge Web Credentials: SAML Tokens",
    "T1056": "Input Capture",
    "T1056.001": "Input Capture: Keylogging",
    "T1056.002": "Input Capture: GUI Input Capture",
    "T1056.003": "Input Capture: Web Portal Capture",
    "T1056.004": "Input Capture: Credential API Hooking",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.001": "Steal or Forge Kerberos Tickets: Golden Ticket",
    "T1558.002": "Steal or Forge Kerberos Tickets: Silver Ticket",
    "T1558.003": "Steal or Forge Kerberos Tickets: Kerberoasting",
    "T1558.004": "Steal or Forge Kerberos Tickets: AS-REP Roasting"
}


def get_mitre_technique_name(technique_id: str) -> str:
    """
    Retorna o nome da técnica MITRE ATT&CK baseado no ID
    
    Args:
        technique_id: ID da técnica (ex: T1566.001)
        
    Returns:
        Nome da técnica ou o próprio ID se não encontrado
    """
    return MITRE_TECHNIQUES.get(technique_id, f"Técnica {technique_id}")


def parse_mitre_techniques(techniques_text: str) -> List[Dict[str, str]]:
    """
    Extrai e parseia técnicas MITRE ATT&CK de um texto
    
    Args:
        techniques_text: Texto contendo técnicas MITRE
        
    Returns:
        Lista de dicionários com informações das técnicas
    """
    techniques = []
    
    # Padrão para encontrar IDs de técnicas MITRE
    pattern = r'T\d{4}(?:\.\d{3})?'
    matches = re.findall(pattern, techniques_text)
    
    for match in matches:
        technique_name = get_mitre_technique_name(match)
        tactic = "Unknown"  # Poderia ser expandido para incluir táticas
        
        techniques.append({
            "id": match,
            "nome": technique_name,
            "tatica": tactic
        })
    
    return techniques 
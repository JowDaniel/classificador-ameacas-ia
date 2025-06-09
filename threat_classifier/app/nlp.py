"""
Módulo de análise de linguagem natural para o Classificador de Ameaças com IA
Responsável pela interação com LLMs, análise semântica e extração de informações
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Carrega variáveis de ambiente do arquivo .env se existir
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # Se python-dotenv não estiver instalado, tenta carregar manualmente
    env_path = Path(__file__).parent.parent.parent / '.env'
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value.strip('"\'')

# Imports condicionais para diferentes provedores de LLM
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from .utils import (
    setup_logging, 
    extract_iocs_from_text, 
    parse_mitre_techniques, 
    get_timestamp,
    get_mitre_technique_name
)


class ThreatAnalyzer:
    """
    Classe responsável pela análise de ameaças usando LLM
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        """
        Inicializa o analisador de ameaças
        
        Args:
            api_key: Chave da API do OpenAI (opcional, pode vir de variável de ambiente)
            model: Modelo a ser usado
        """
        self.logger = logging.getLogger(__name__)
        self.model = model
        
        # Configura cliente OpenAI se disponível
        if OPENAI_AVAILABLE:
            self.api_key = api_key or os.getenv('OPENAI_API_KEY')
            if self.api_key:
                openai.api_key = self.api_key
                self.llm_available = True
            else:
                self.logger.warning("API Key do OpenAI não encontrada. Algumas funcionalidades ficarão limitadas.")
                self.llm_available = False
        else:
            self.logger.warning("OpenAI não está instalado. Usando análise básica apenas.")
            self.llm_available = False
    
    def analyze_report(self, text: str, source_info: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Analisa um relatório completo extraindo IoCs, classificando ameaças e mapeando MITRE
        
        Args:
            text: Texto do relatório
            source_info: Informações sobre a fonte do relatório
            
        Returns:
            Dicionário estruturado com toda a análise
        """
        self.logger.info("Iniciando análise completa do relatório")
        
        # Estrutura base do resultado
        result = {
            "iocs": {},
            "tipo_ameaca": "Não identificado",
            "mitre": [],
            "fonte": source_info.get("filename", "Unknown") if source_info else "Unknown",
            "data_analise": get_timestamp(),
            "resumo": "",
            "confianca": 0.0,
            "metadados": {
                "palavras_analisadas": len(text.split()) if text else 0,
                "modelo_usado": self.model if self.llm_available else "regex_only",
                "fonte_dados": source_info
            }
        }
        
        if not text or len(text.strip()) < 50:
            self.logger.warning("Texto muito curto para análise")
            return result
        
        try:
            # 1. Extração de IoCs
            result["iocs"] = self.extract_iocs(text)
            
            # 2. Classificação do tipo de ameaça
            result["tipo_ameaca"] = self.classify_threat_type(text)
            
            # 3. Mapeamento MITRE ATT&CK
            result["mitre"] = self.extract_mitre_mapping(text)
            
            # 4. Geração de resumo
            result["resumo"] = self.generate_summary(text)
            
            # 5. Cálculo de confiança
            result["confianca"] = self._calculate_confidence(result)
            
            self.logger.info("Análise completa concluída com sucesso")
            
        except Exception as e:
            self.logger.error(f"Erro durante análise: {e}")
            result["erro"] = str(e)
        
        return result
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """
        Extrai Indicadores de Compromisso (IoCs) do texto
        
        Args:
            text: Texto para análise
            
        Returns:
            Dicionário com IoCs categorizados
        """
        # Extração básica com regex
        basic_iocs = extract_iocs_from_text(text)
        
        # Se LLM disponível, melhora a extração
        if self.llm_available:
            try:
                enhanced_iocs = self._extract_iocs_with_llm(text)
                # Combina resultados
                for category in basic_iocs:
                    if category in enhanced_iocs:
                        # Remove duplicatas e combina
                        combined = list(set(basic_iocs[category] + enhanced_iocs[category]))
                        basic_iocs[category] = combined
                
                # Adiciona categorias que só o LLM encontrou
                for category, values in enhanced_iocs.items():
                    if category not in basic_iocs:
                        basic_iocs[category] = values
                        
            except Exception as e:
                self.logger.warning(f"Erro na extração avançada de IoCs: {e}")
        
        return basic_iocs
    
    def classify_threat_type(self, text: str) -> str:
        """
        Classifica o tipo de ameaça baseado no texto
        
        Args:
            text: Texto para análise
            
        Returns:
            Tipo de ameaça identificado
        """
        # Classificação básica por palavras-chave
        basic_classification = self._classify_basic_threat(text)
        
        # Se LLM disponível, faz classificação mais sofisticada
        if self.llm_available:
            try:
                return self._classify_threat_with_llm(text)
            except Exception as e:
                self.logger.warning(f"Erro na classificação avançada: {e}")
        
        return basic_classification
    
    def extract_mitre_mapping(self, text: str) -> List[Dict[str, str]]:
        """
        Extrai mapeamento para o framework MITRE ATT&CK
        
        Args:
            text: Texto para análise
            
        Returns:
            Lista de técnicas MITRE identificadas
        """
        # Se LLM disponível, usa análise avançada
        if self.llm_available:
            try:
                enhanced_techniques = self._extract_mitre_with_llm(text)
                if enhanced_techniques:
                    return enhanced_techniques
                        
            except Exception as e:
                self.logger.warning(f"Erro no mapeamento MITRE avançado: {e}")
        
        # Fallback melhorado
        return self._extract_mitre_techniques_fallback(text)
    
    def generate_summary(self, text: str) -> str:
        """
        Gera resumo do relatório
        
        Args:
            text: Texto completo
            
        Returns:
            Resumo do relatório
        """
        if self.llm_available:
            try:
                return self._generate_summary_with_llm(text)
            except Exception as e:
                self.logger.warning(f"Erro na geração de resumo: {e}")
        
        # Resumo básico - primeiras e últimas sentenças
        sentences = text.split('.')
        if len(sentences) > 3:
            summary_sentences = sentences[:2] + sentences[-1:]
            return '. '.join(summary_sentences).strip()
        
        return text[:500] + "..." if len(text) > 500 else text
    
    def _extract_iocs_with_llm(self, text: str) -> Dict[str, List[str]]:
        """
        Extrai IoCs usando LLM
        """
        prompt = """
        Você é um analista de CTI especializado. Extraia TODOS os Indicadores de Compromisso (IoCs) do texto abaixo.
        
        Categorize os IoCs encontrados em:
        - ips: Endereços IP
        - dominios: Nomes de domínio
        - urls: URLs completas
        - hashes: Hashes MD5, SHA1, SHA256
        - emails: Endereços de email
        - arquivos: Nomes de arquivos maliciosos
        - registry: Chaves de registro
        - mutexes: Nomes de mutex
        - processos: Nomes de processos
        
        Retorne APENAS um JSON válido no formato:
        {
          "ips": [...],
          "dominios": [...],
          "urls": [...],
          "hashes": [...],
          "emails": [...],
          "arquivos": [...],
          "registry": [...],
          "mutexes": [...],
          "processos": [...]
        }
        
        Texto: """ + text[:4000]  # Limita o texto para não exceder token limit
        
        response = openai.ChatCompletion.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=1500
        )
        
        response_text = response.choices[0].message.content.strip()
        
        # Tenta extrair JSON da resposta
        try:
            # Remove markdown se presente
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0]
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0]
            
            return json.loads(response_text)
        except json.JSONDecodeError:
            self.logger.error("Erro ao parsear resposta JSON do LLM")
            return {}
    
    def _classify_threat_with_llm(self, text: str) -> str:
        """
        Classifica ameaça usando LLM
        """
        prompt = """
        Você é um analista de segurança cibernética. Classifique o tipo de ameaça descrita no texto abaixo.
        
        Escolha uma das seguintes categorias:
        - APT (Advanced Persistent Threat)
        - Ransomware
        - Malware
        - Phishing
        - Spyware
        - Trojan
        - Botnet
        - Insider Threat
        - Social Engineering
        - DDoS
        - Data Breach
        - Zero-day Exploit
        - Supply Chain Attack
        - Outro
        
        Responda APENAS com o nome da categoria, sem explicações adicionais.
        
        Texto: """ + text[:3000]
        
        response = openai.ChatCompletion.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=50
        )
        
        return response.choices[0].message.content.strip()
    
    def _extract_mitre_with_llm(self, text: str) -> List[Dict[str, str]]:
        """
        Extrai técnicas MITRE usando LLM
        """
        prompt = """
        Você é um especialista em MITRE ATT&CK. Identifique todas as táticas e técnicas MITRE ATT&CK mencionadas ou inferidas no texto abaixo.
        
        Para cada técnica identificada, forneça:
        - ID da técnica (formato T1234 ou T1234.001)
        - Nome da técnica
        - Tática associada
        
        Retorne APENAS um JSON válido no formato:
        [
          {
            "id": "T1059",
            "nome": "Command and Scripting Interpreter",
            "tatica": "Execution"
          }
        ]
        
        Se não encontrar técnicas específicas, retorne uma lista vazia [].
        
        Texto: """ + text[:3500]
        
        response = openai.ChatCompletion.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=1000
        )
        
        response_text = response.choices[0].message.content.strip()
        
        try:
            # Remove markdown se presente
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0]
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0]
            
            return json.loads(response_text)
        except json.JSONDecodeError:
            self.logger.error("Erro ao parsear resposta JSON do MITRE")
            return []
    
    def _generate_summary_with_llm(self, text: str) -> str:
        """
        Gera resumo usando LLM
        """
        prompt = """
        Você é um analista de CTI. Crie um resumo executivo conciso do relatório de segurança abaixo.
        
        O resumo deve:
        - Ter no máximo 3 parágrafos
        - Destacar os principais achados
        - Mencionar o tipo de ameaça
        - Incluir principais IoCs se relevantes
        - Ser claro e objetivo
        
        Texto: """ + text[:4000]
        
        response = openai.ChatCompletion.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=500
        )
        
        return response.choices[0].message.content.strip()
    
    def _classify_basic_threat(self, text: str) -> str:
        """
        Classificação básica por palavras-chave
        """
        text_lower = text.lower()
        
        threat_keywords = {
            "Ransomware": ["ransom", "encrypt", "decrypt", "payment", "bitcoin", "crypto"],
            "APT": ["apt", "advanced persistent", "nation state", "sophisticated"],
            "Phishing": ["phish", "fake email", "credential", "spoofing", "social engineering"],
            "Malware": ["malware", "virus", "trojan", "backdoor", "payload"],
            "DDoS": ["ddos", "distributed denial", "amplification", "botnet attack"],
            "Data Breach": ["data breach", "exfiltration", "stolen data", "leak"],
            "Botnet": ["botnet", "command and control", "c2", "zombie"]
        }
        
        scores = {}
        for threat_type, keywords in threat_keywords.items():
            score = sum(1 for keyword in keywords if keyword in text_lower)
            if score > 0:
                scores[threat_type] = score
        
        if scores:
            return max(scores.items(), key=lambda x: x[1])[0]
        
        return "Não identificado"
    
    def _calculate_confidence(self, analysis_result: Dict[str, Any]) -> float:
        """
        Calcula nível de confiança da análise
        """
        confidence = 0.0
        
        # IoCs encontrados aumentam confiança
        total_iocs = sum(len(iocs) for iocs in analysis_result["iocs"].values())
        if total_iocs > 0:
            confidence += min(0.3, total_iocs * 0.05)
        
        # Tipo de ameaça identificado
        if analysis_result["tipo_ameaca"] != "Não identificado":
            confidence += 0.2
        
        # Técnicas MITRE encontradas
        mitre_count = len(analysis_result["mitre"])
        if mitre_count > 0:
            confidence += min(0.3, mitre_count * 0.1)
        
        # Resumo gerado
        if analysis_result["resumo"] and len(analysis_result["resumo"]) > 50:
            confidence += 0.2
        
        # Ajuste baseado no tamanho do texto
        word_count = analysis_result["metadados"]["palavras_analisadas"]
        if word_count > 500:
            confidence += 0.1
        elif word_count < 100:
            confidence -= 0.1
        
        return min(1.0, max(0.0, confidence))

    def _extract_mitre_techniques_fallback(self, text: str) -> List[Dict[str, str]]:
        """
        Fallback para extração de técnicas MITRE usando regex
        
        Args:
            text: Texto para análise
            
        Returns:
            Lista de técnicas MITRE encontradas
        """
        self.logger.info("Usando fallback regex para técnicas MITRE")
        
        # Usa a função melhorada do utils
        techniques = parse_mitre_techniques(text)
        
        # Se não encontrou nenhuma, adiciona algumas técnicas comuns baseadas em palavras-chave
        if not techniques:
            common_techniques = []
            
            text_lower = text.lower()
            
            # Mapeamento de palavras-chave para técnicas MITRE
            keyword_mappings = {
                "phishing": ["T1566.001", "T1566.002"],
                "email": ["T1566.001", "T1114"],
                "attachment": ["T1566.001"],
                "ransomware": ["T1486"],
                "encryption": ["T1486"],
                "powershell": ["T1059.001"],
                "command": ["T1059"],
                "script": ["T1059"],
                "persistence": ["T1053", "T1136"],
                "privilege": ["T1078", "T1134"],
                "credential": ["T1003.001", "T1552"],
                "injection": ["T1055"],
                "discovery": ["T1082", "T1083", "T1087"],
                "lateral": ["T1021"],
                "exfiltration": ["T1041", "T1048"]
            }
            
            for keyword, technique_ids in keyword_mappings.items():
                if keyword in text_lower:
                    for tech_id in technique_ids:
                        technique_name = get_mitre_technique_name(tech_id)
                        tactic = self._get_tactic_for_technique(tech_id)
                        
                        common_techniques.append({
                            "id": tech_id,
                            "nome": technique_name,
                            "tatica": tactic
                        })
            
            # Remove duplicatas
            seen = set()
            techniques = []
            for tech in common_techniques:
                if tech["id"] not in seen:
                    techniques.append(tech)
                    seen.add(tech["id"])
        
        return techniques[:10]  # Limita a 10 técnicas
    
    def _get_tactic_for_technique(self, technique_id: str) -> str:
        """
        Retorna a tática MITRE para uma técnica
        
        Args:
            technique_id: ID da técnica
            
        Returns:
            Nome da tática
        """
        # Mapeamento simplificado de técnicas para táticas
        tactic_mappings = {
            "T1566": "Initial Access",
            "T1486": "Impact", 
            "T1027": "Defense Evasion",
            "T1078": "Persistence",
            "T1134": "Privilege Escalation",
            "T1003": "Credential Access",
            "T1204": "Execution",
            "T1055": "Defense Evasion",
            "T1059": "Execution",
            "T1047": "Execution",
            "T1053": "Persistence",
            "T1136": "Persistence",
            "T1082": "Discovery",
            "T1083": "Discovery",
            "T1087": "Discovery",
            "T1016": "Discovery",
            "T1033": "Discovery",
            "T1049": "Discovery",
            "T1057": "Discovery",
            "T1518": "Discovery",
            "T1012": "Discovery",
            "T1124": "Discovery",
            "T1007": "Discovery",
            "T1135": "Discovery",
            "T1046": "Discovery",
            "T1040": "Credential Access",
            "T1018": "Discovery",
            "T1041": "Exfiltration",
            "T1048": "Exfiltration",
            "T1567": "Exfiltration",
            "T1005": "Collection",
            "T1039": "Collection",
            "T1025": "Collection",
            "T1074": "Collection",
            "T1560": "Collection",
            "T1119": "Collection",
            "T1114": "Collection",
            "T1115": "Collection",
            "T1113": "Collection",
            "T1125": "Collection",
            "T1123": "Collection",
            "T1185": "Collection",
            "T1539": "Credential Access",
            "T1552": "Credential Access",
            "T1110": "Credential Access",
            "T1212": "Credential Access",
            "T1187": "Credential Access",
            "T1606": "Credential Access",
            "T1056": "Credential Access",
            "T1558": "Credential Access"
        }
        
        # Busca por prefixo (T1566 para T1566.001)
        base_id = technique_id.split('.')[0]
        return tactic_mappings.get(base_id, "Unknown") 
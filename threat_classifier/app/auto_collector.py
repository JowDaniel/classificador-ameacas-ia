"""
Módulo de coleta automática de relatórios de segurança
Coleta dados de feeds RSS, APIs públicas e outras fontes
"""

import asyncio
import aiohttp
import feedparser
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import schedule
import threading
from urllib.parse import urljoin, urlparse

from .collector import DataCollector
from .database import ThreatDatabase
from .nlp import ThreatAnalyzer
from .utils import get_timestamp, setup_logging


class AutoCollector:
    """
    Sistema de coleta automática de relatórios de segurança
    """
    
    def __init__(self, db: ThreatDatabase, nlp: ThreatAnalyzer):
        """
        Inicializa o coletor automático
        
        Args:
            db: Instância do banco de dados
            nlp: Instância do analisador NLP
        """
        self.db = db
        self.nlp = nlp
        self.collector = DataCollector()
        self.logger = logging.getLogger(__name__)
        
        # Configuração de fontes
        self.sources = self._load_sources()
        
        # Controle de execução
        self.is_running = False
        self.scheduler_thread = None
        
        # Estatísticas
        self.stats = {
            "total_collected": 0,
            "successful_collections": 0,
            "failed_collections": 0,
            "last_run": None
        }
    
    def _load_sources(self) -> Dict[str, Dict]:
        """
        Carrega configuração das fontes de dados
        """
        return {
            "cisa_alerts": {
                "name": "CISA Security Alerts",
                "type": "rss",
                "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
                "enabled": True,
                "frequency": "daily",
                "category": "governo"
            },
            "us_cert": {
                "name": "US-CERT Alerts",
                "type": "rss", 
                "url": "https://www.us-cert.gov/channels/alerts.rss",
                "enabled": True,
                "frequency": "daily",
                "category": "governo"
            },
            "sans_isc": {
                "name": "SANS Internet Storm Center",
                "type": "rss",
                "url": "https://isc.sans.edu/rssfeed.xml",
                "enabled": True,
                "frequency": "hourly",
                "category": "pesquisa"
            },
            "krebs_security": {
                "name": "Krebs on Security",
                "type": "rss",
                "url": "https://krebsonsecurity.com/feed/",
                "enabled": True,
                "frequency": "daily",
                "category": "noticias"
            },
            "threatpost": {
                "name": "Threatpost",
                "type": "rss",
                "url": "https://threatpost.com/feed/",
                "enabled": True,
                "frequency": "hourly",
                "category": "noticias"
            },
            "bleeping_computer": {
                "name": "Bleeping Computer Security",
                "type": "rss",
                "url": "https://www.bleepingcomputer.com/feed/",
                "enabled": True,
                "frequency": "hourly",
                "category": "noticias"
            },
            "mitre_cve": {
                "name": "MITRE CVE Recent",
                "type": "api",
                "url": "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2024.xml",
                "enabled": True,
                "frequency": "daily",
                "category": "vulnerabilidades"
            },
            "nvd_recent": {
                "name": "NVD Recent Vulnerabilities",
                "type": "api",
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "enabled": True,
                "frequency": "daily",
                "category": "vulnerabilidades"
            },
            "cisa_kev": {
                "name": "CISA Known Exploited Vulnerabilities",
                "type": "json",
                "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "enabled": True,
                "frequency": "daily",
                "category": "vulnerabilidades"
            },
            "malware_bazaar": {
                "name": "Malware Bazaar Recent",
                "type": "api",
                "url": "https://mb-api.abuse.ch/api/v1/",
                "enabled": True,
                "frequency": "hourly",
                "category": "malware"
            }
        }
    
    def start_scheduler(self):
        """
        Inicia o agendador de coletas automáticas
        """
        if self.is_running:
            self.logger.warning("Scheduler já está rodando")
            return
        
        self.logger.info("Iniciando scheduler de coleta automática")
        
        # Agenda coletas por frequência
        for source_id, config in self.sources.items():
            if not config.get("enabled", True):
                continue
                
            frequency = config.get("frequency", "daily")
            
            if frequency == "hourly":
                schedule.every().hour.do(self._collect_from_source, source_id)
            elif frequency == "daily":
                schedule.every().day.at("09:00").do(self._collect_from_source, source_id)
            elif frequency == "weekly":
                schedule.every().week.do(self._collect_from_source, source_id)
        
        # Inicia thread do scheduler
        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        self.logger.info("Scheduler iniciado com sucesso")
    
    def stop_scheduler(self):
        """
        Para o agendador de coletas
        """
        self.logger.info("Parando scheduler de coleta automática")
        self.is_running = False
        schedule.clear()
        
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            self.scheduler_thread.join(timeout=5)
        
        self.logger.info("Scheduler parado")
    
    def _run_scheduler(self):
        """
        Loop principal do scheduler
        """
        while self.is_running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Verifica a cada minuto
            except Exception as e:
                self.logger.error(f"Erro no scheduler: {e}")
                time.sleep(300)  # Espera 5 minutos em caso de erro
    
    async def collect_all_sources(self) -> Dict[str, Any]:
        """
        Coleta de todas as fontes habilitadas
        """
        self.logger.info("Iniciando coleta de todas as fontes")
        results = {
            "timestamp": get_timestamp(),
            "sources": {},
            "summary": {
                "total_sources": 0,
                "successful": 0,
                "failed": 0,
                "new_reports": 0
            }
        }
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            tasks = []
            
            for source_id, config in self.sources.items():
                if config.get("enabled", True):
                    task = self._collect_from_source_async(session, source_id, config)
                    tasks.append(task)
            
            # Executa coletas em paralelo
            source_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Processa resultados
            for i, (source_id, config) in enumerate([item for item in self.sources.items() if item[1].get("enabled", True)]):
                result = source_results[i]
                results["sources"][source_id] = result
                results["summary"]["total_sources"] += 1
                
                if isinstance(result, Exception):
                    results["summary"]["failed"] += 1
                    self.logger.error(f"Erro na fonte {source_id}: {result}")
                else:
                    results["summary"]["successful"] += 1
                    results["summary"]["new_reports"] += result.get("new_reports", 0)
        
        # Atualiza estatísticas
        self.stats["last_run"] = get_timestamp()
        self.stats["total_collected"] += results["summary"]["total_sources"]
        self.stats["successful_collections"] += results["summary"]["successful"]
        self.stats["failed_collections"] += results["summary"]["failed"]
        
        self.logger.info(f"Coleta concluída: {results['summary']}")
        return results
    
    async def _collect_from_source_async(self, session: aiohttp.ClientSession, source_id: str, config: Dict) -> Dict[str, Any]:
        """
        Coleta dados de uma fonte específica (async)
        """
        source_type = config.get("type", "rss")
        
        try:
            if source_type == "rss":
                return await self._collect_rss_feed(session, source_id, config)
            elif source_type == "json":
                return await self._collect_json_feed(session, source_id, config)
            elif source_type == "api":
                return await self._collect_api_data(session, source_id, config)
            else:
                raise ValueError(f"Tipo de fonte não suportado: {source_type}")
                
        except Exception as e:
            self.logger.error(f"Erro coletando fonte {source_id}: {e}")
            return {"error": str(e), "new_reports": 0}
    
    def _collect_from_source(self, source_id: str):
        """
        Wrapper síncrono para coleta de fonte individual
        """
        config = self.sources.get(source_id)
        if not config:
            self.logger.error(f"Fonte não encontrada: {source_id}")
            return
        
        asyncio.run(self._collect_single_source(source_id, config))
    
    async def _collect_single_source(self, source_id: str, config: Dict):
        """
        Coleta uma única fonte
        """
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            result = await self._collect_from_source_async(session, source_id, config)
            self.logger.info(f"Fonte {source_id}: {result}")
    
    async def _collect_rss_feed(self, session: aiohttp.ClientSession, source_id: str, config: Dict) -> Dict[str, Any]:
        """
        Coleta dados de feed RSS/Atom
        """
        url = config["url"]
        self.logger.info(f"Coletando RSS: {config['name']}")
        
        async with session.get(url) as response:
            if response.status != 200:
                raise Exception(f"HTTP {response.status} para {url}")
            
            content = await response.text()
            
        # Parse do feed RSS
        feed = feedparser.parse(content)
        
        if feed.bozo:
            self.logger.warning(f"Feed RSS com problemas: {source_id}")
        
        new_reports = 0
        processed_entries = []
        
        # Processa entradas do feed
        for entry in feed.entries[:20]:  # Limita a 20 mais recentes
            try:
                # Extrai informações básicas
                title = entry.get("title", "Sem título")
                link = entry.get("link", "")
                description = entry.get("description", entry.get("summary", ""))
                published = entry.get("published", "")
                
                # Monta identificador único
                entry_id = f"{source_id}_{hash(link)}_{hash(title)}"
                
                # Verifica se já foi coletado
                if self.db.report_exists_by_source(entry_id):
                    continue
                
                # Coleta conteúdo completo da URL
                if link:
                    try:
                        full_content = await self._fetch_url_content(session, link)
                        if full_content and len(full_content) > 200:
                            content_to_analyze = full_content
                        else:
                            content_to_analyze = f"{title}\n\n{description}"
                    except:
                        content_to_analyze = f"{title}\n\n{description}"
                else:
                    content_to_analyze = f"{title}\n\n{description}"
                
                # Analisa com IA se conteúdo suficiente
                if len(content_to_analyze.strip()) > 100:
                    source_info = {
                        "filename": entry_id,
                        "source_type": "rss_auto",
                        "source_name": config["name"],
                        "original_url": link,
                        "published_date": published,
                        "category": config.get("category", "unknown")
                    }
                    
                    analysis = self.nlp.analyze_report(content_to_analyze, source_info)
                    
                    if analysis and analysis.get("tipo_ameaca") != "Não identificado":
                        # Salva apenas se encontrou ameaças relevantes
                        report_id = self.db.save_analysis(analysis)
                        if report_id:
                            new_reports += 1
                            processed_entries.append({
                                "title": title,
                                "url": link,
                                "threat_type": analysis["tipo_ameaca"],
                                "confidence": analysis["confianca"]
                            })
            
            except Exception as e:
                self.logger.warning(f"Erro processando entrada RSS: {e}")
                continue
        
        return {
            "source": config["name"],
            "type": "rss",
            "new_reports": new_reports,
            "processed_entries": processed_entries,
            "total_entries": len(feed.entries)
        }
    
    async def _collect_json_feed(self, session: aiohttp.ClientSession, source_id: str, config: Dict) -> Dict[str, Any]:
        """
        Coleta dados de feed JSON
        """
        url = config["url"]
        self.logger.info(f"Coletando JSON: {config['name']}")
        
        async with session.get(url) as response:
            if response.status != 200:
                raise Exception(f"HTTP {response.status} para {url}")
            
            data = await response.json()
        
        new_reports = 0
        processed_items = []
        
        # Processa dados específicos por fonte
        if source_id == "cisa_kev":
            # CISA Known Exploited Vulnerabilities
            vulnerabilities = data.get("vulnerabilities", [])
            
            for vuln in vulnerabilities[:50]:  # Limita a 50 mais recentes
                try:
                    cve_id = vuln.get("cveID", "")
                    
                    # Verifica se já foi processado
                    entry_id = f"cisa_kev_{cve_id}"
                    if self.db.report_exists_by_source(entry_id):
                        continue
                    
                    # Monta conteúdo para análise
                    content = f"""
                    CVE ID: {cve_id}
                    Vendor Project: {vuln.get('vendorProject', '')}
                    Product: {vuln.get('product', '')}
                    Vulnerability Name: {vuln.get('vulnerabilityName', '')}
                    Date Added to Catalog: {vuln.get('dateAdded', '')}
                    Short Description: {vuln.get('shortDescription', '')}
                    Required Action: {vuln.get('requiredAction', '')}
                    Due Date: {vuln.get('dueDate', '')}
                    """
                    
                    source_info = {
                        "filename": entry_id,
                        "source_type": "cisa_kev",
                        "source_name": config["name"],
                        "cve_id": cve_id,
                        "category": "vulnerabilidades"
                    }
                    
                    analysis = self.nlp.analyze_report(content, source_info)
                    
                    if analysis:
                        report_id = self.db.save_analysis(analysis)
                        if report_id:
                            new_reports += 1
                            processed_items.append({
                                "cve_id": cve_id,
                                "product": vuln.get('product', ''),
                                "threat_type": analysis["tipo_ameaca"],
                                "confidence": analysis["confianca"]
                            })
                
                except Exception as e:
                    self.logger.warning(f"Erro processando vulnerability: {e}")
                    continue
        
        return {
            "source": config["name"],
            "type": "json",
            "new_reports": new_reports,
            "processed_items": processed_items
        }
    
    async def _collect_api_data(self, session: aiohttp.ClientSession, source_id: str, config: Dict) -> Dict[str, Any]:
        """
        Coleta dados de APIs específicas
        """
        url = config["url"]
        self.logger.info(f"Coletando API: {config['name']}")
        
        new_reports = 0
        
        # Implementação específica por API
        if source_id == "nvd_recent":
            # National Vulnerability Database
            # Coleta CVEs dos últimos 7 dias
            end_date = datetime.now()
            start_date = end_date - timedelta(days=7)
            
            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
                "resultsPerPage": 50
            }
            
            async with session.get(url, params=params) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status} para NVD API")
                
                data = await response.json()
                
                for cve in data.get("vulnerabilities", []):
                    try:
                        cve_data = cve.get("cve", {})
                        cve_id = cve_data.get("id", "")
                        
                        entry_id = f"nvd_{cve_id}"
                        if self.db.report_exists_by_source(entry_id):
                            continue
                        
                        # Extrai descrição
                        descriptions = cve_data.get("descriptions", [])
                        description = ""
                        for desc in descriptions:
                            if desc.get("lang") == "en":
                                description = desc.get("value", "")
                                break
                        
                        # Monta conteúdo
                        content = f"""
                        CVE ID: {cve_id}
                        Published: {cve_data.get('published', '')}
                        Last Modified: {cve_data.get('lastModified', '')}
                        Description: {description}
                        """
                        
                        source_info = {
                            "filename": entry_id,
                            "source_type": "nvd_api",
                            "source_name": config["name"],
                            "cve_id": cve_id,
                            "category": "vulnerabilidades"
                        }
                        
                        analysis = self.nlp.analyze_report(content, source_info)
                        
                        if analysis:
                            report_id = self.db.save_analysis(analysis)
                            if report_id:
                                new_reports += 1
                    
                    except Exception as e:
                        self.logger.warning(f"Erro processando CVE: {e}")
                        continue
        
        return {
            "source": config["name"],
            "type": "api",
            "new_reports": new_reports
        }
    
    async def _fetch_url_content(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """
        Busca conteúdo completo de uma URL
        """
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    content = await response.text()
                    # Remove HTML básico se necessário
                    if "<html" in content.lower():
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(content, 'html.parser')
                        return soup.get_text()
                    return content
        except:
            pass
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Retorna estatísticas do coletor automático
        """
        enabled_sources = [s for s in self.sources.values() if s.get("enabled", True)]
        
        return {
            "is_running": self.is_running,
            "total_sources": len(self.sources),
            "enabled_sources": len(enabled_sources),
            "sources_by_category": self._get_sources_by_category(),
            "stats": self.stats,
            "next_scheduled": self._get_next_scheduled_runs()
        }
    
    def _get_sources_by_category(self) -> Dict[str, int]:
        """
        Conta fontes por categoria
        """
        categories = {}
        for config in self.sources.values():
            if config.get("enabled", True):
                category = config.get("category", "unknown")
                categories[category] = categories.get(category, 0) + 1
        return categories
    
    def _get_next_scheduled_runs(self) -> List[str]:
        """
        Obtém próximas execuções agendadas
        """
        if not self.is_running:
            return []
        
        jobs = schedule.get_jobs()
        return [str(job.next_run) for job in jobs[:5]]  # Próximas 5
    
    def enable_source(self, source_id: str):
        """
        Habilita uma fonte específica
        """
        if source_id in self.sources:
            self.sources[source_id]["enabled"] = True
            self.logger.info(f"Fonte habilitada: {source_id}")
    
    def disable_source(self, source_id: str):
        """
        Desabilita uma fonte específica
        """
        if source_id in self.sources:
            self.sources[source_id]["enabled"] = False
            self.logger.info(f"Fonte desabilitada: {source_id}")
    
    def get_sources_status(self) -> Dict[str, Dict]:
        """
        Retorna status de todas as fontes
        """
        return self.sources.copy() 
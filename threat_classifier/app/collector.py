"""
Módulo de coleta de relatórios para o Classificador de Ameaças com IA
Responsável por baixar relatórios de fontes públicas e gerenciar uploads manuais
"""

import os
import requests
import logging
from pathlib import Path
from typing import List, Optional, Dict
from urllib.parse import urlparse, urljoin
from datetime import datetime
import shutil

from .utils import sanitize_filename, ensure_directory_exists, get_timestamp


class ReportCollector:
    """
    Classe responsável pela coleta de relatórios de incidentes cibernéticos
    """
    
    def __init__(self, data_folder: str = "data"):
        """
        Inicializa o coletor de relatórios
        
        Args:
            data_folder: Pasta onde armazenar os relatórios baixados
        """
        self.data_folder = Path(data_folder)
        ensure_directory_exists(str(self.data_folder))
        self.logger = logging.getLogger(__name__)
        
        # Headers padrão para requisições
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def download_reports(self, sources: List[str], dest_folder: Optional[str] = None) -> List[Dict[str, str]]:
        """
        Baixa relatórios de uma lista de URLs
        
        Args:
            sources: Lista de URLs para baixar
            dest_folder: Pasta de destino (opcional)
            
        Returns:
            Lista de dicionários com informações dos arquivos baixados
        """
        if dest_folder is None:
            dest_folder = self.data_folder
        else:
            dest_folder = Path(dest_folder)
            ensure_directory_exists(str(dest_folder))
        
        downloaded_files = []
        
        for url in sources:
            try:
                result = self._download_single_report(url, dest_folder)
                if result:
                    downloaded_files.append(result)
            except Exception as e:
                self.logger.error(f"Erro ao baixar relatório de {url}: {e}")
                continue
        
        self.logger.info(f"Download concluído. {len(downloaded_files)} arquivos baixados com sucesso.")
        return downloaded_files
    
    def _download_single_report(self, url: str, dest_folder: Path) -> Optional[Dict[str, str]]:
        """
        Baixa um único relatório
        
        Args:
            url: URL do relatório
            dest_folder: Pasta de destino
            
        Returns:
            Dicionário com informações do arquivo baixado ou None se erro
        """
        try:
            self.logger.info(f"Baixando relatório de: {url}")
            
            # Faz a requisição
            response = requests.get(url, headers=self.headers, timeout=30, stream=True)
            response.raise_for_status()
            
            # Determina o nome do arquivo
            filename = self._get_filename_from_url(url, response)
            file_path = dest_folder / filename
            
            # Baixa o arquivo
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            # Determina o tipo de arquivo
            file_type = self._get_file_type(file_path)
            
            file_info = {
                "url": url,
                "local_path": str(file_path),
                "filename": filename,
                "file_type": file_type,
                "size": file_path.stat().st_size,
                "download_date": get_timestamp(),
                "source": "download"
            }
            
            self.logger.info(f"Arquivo baixado com sucesso: {filename}")
            return file_info
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Erro de rede ao baixar {url}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Erro inesperado ao baixar {url}: {e}")
            return None
    
    def _get_filename_from_url(self, url: str, response: requests.Response) -> str:
        """
        Determina o nome do arquivo baseado na URL e headers da resposta
        
        Args:
            url: URL do arquivo
            response: Resposta HTTP
            
        Returns:
            Nome do arquivo sanitizado
        """
        # Tenta obter o nome do header Content-Disposition
        content_disposition = response.headers.get('content-disposition')
        if content_disposition:
            import re
            filename_match = re.search(r'filename[^;=\n]*=(([\'"]).*?\2|[^;\n]*)', content_disposition)
            if filename_match:
                filename = filename_match.group(1).strip('\'"')
                return sanitize_filename(filename)
        
        # Se não conseguir, usa o nome da URL
        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path)
        
        if not filename or '.' not in filename:
            # Se ainda não tiver nome, gera um baseado no timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Tenta determinar a extensão pelo Content-Type
            content_type = response.headers.get('content-type', '').lower()
            if 'pdf' in content_type:
                extension = '.pdf'
            elif 'html' in content_type:
                extension = '.html'
            elif 'text' in content_type:
                extension = '.txt'
            else:
                extension = '.bin'
            
            filename = f"report_{timestamp}{extension}"
        
        return sanitize_filename(filename)
    
    def _get_file_type(self, file_path: Path) -> str:
        """
        Determina o tipo do arquivo baseado na extensão
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Tipo do arquivo
        """
        extension = file_path.suffix.lower()
        
        type_mapping = {
            '.pdf': 'pdf',
            '.html': 'html',
            '.htm': 'html',
            '.txt': 'text',
            '.doc': 'word',
            '.docx': 'word',
            '.xml': 'xml',
            '.json': 'json'
        }
        
        return type_mapping.get(extension, 'unknown')
    
    def manual_upload(self, file_path: str, dest_folder: Optional[str] = None) -> Optional[Dict[str, str]]:
        """
        Processa upload manual de arquivo
        
        Args:
            file_path: Caminho do arquivo a ser copiado
            dest_folder: Pasta de destino (opcional)
            
        Returns:
            Dicionário com informações do arquivo ou None se erro
        """
        if dest_folder is None:
            dest_folder = self.data_folder
        else:
            dest_folder = Path(dest_folder)
            ensure_directory_exists(str(dest_folder))
        
        try:
            source_path = Path(file_path)
            
            if not source_path.exists():
                self.logger.error(f"Arquivo não encontrado: {file_path}")
                return None
            
            # Copia o arquivo para a pasta de destino
            filename = sanitize_filename(source_path.name)
            dest_path = dest_folder / filename
            
            # Se arquivo já existe, adiciona timestamp
            if dest_path.exists():
                timestamp = datetime.now().strftime("_%Y%m%d_%H%M%S")
                name_parts = filename.rsplit('.', 1)
                if len(name_parts) == 2:
                    filename = f"{name_parts[0]}{timestamp}.{name_parts[1]}"
                else:
                    filename = f"{filename}{timestamp}"
                dest_path = dest_folder / filename
            
            shutil.copy2(source_path, dest_path)
            
            file_info = {
                "url": f"file://{source_path.absolute()}",
                "local_path": str(dest_path),
                "filename": filename,
                "file_type": self._get_file_type(dest_path),
                "size": dest_path.stat().st_size,
                "download_date": get_timestamp(),
                "source": "manual_upload"
            }
            
            self.logger.info(f"Arquivo copiado com sucesso: {filename}")
            return file_info
            
        except Exception as e:
            self.logger.error(f"Erro ao fazer upload do arquivo {file_path}: {e}")
            return None
    
    def list_downloaded_files(self) -> List[Dict[str, str]]:
        """
        Lista todos os arquivos na pasta de dados
        
        Returns:
            Lista de dicionários com informações dos arquivos
        """
        files = []
        
        if not self.data_folder.exists():
            return files
        
        for file_path in self.data_folder.iterdir():
            if file_path.is_file():
                file_info = {
                    "local_path": str(file_path),
                    "filename": file_path.name,
                    "file_type": self._get_file_type(file_path),
                    "size": file_path.stat().st_size,
                    "modified_date": datetime.fromtimestamp(file_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                }
                files.append(file_info)
        
        return files
    
    def get_sample_sources(self) -> List[str]:
        """
        Retorna lista de fontes de exemplo para demonstração
        
        Returns:
            Lista de URLs de exemplo
        """
        return [
            "https://www.cisa.gov/sites/default/files/publications/CISA_AA20-266A_Ransomware_Activity_Targeting_The_Healthcare_And_Public_Health_Sector.pdf",
            "https://attack.mitre.org/docs/enterprise-attack-v13.1.pdf",
            "https://www.crowdstrike.com/resources/reports/threat-intel-report/"
        ] 
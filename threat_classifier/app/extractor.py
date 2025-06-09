"""
Módulo de extração de texto para o Classificador de Ameaças com IA
Responsável por extrair e limpar texto de arquivos PDF, HTML e outros formatos
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any
import re

# Imports condicionais para diferentes tipos de arquivo
try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

from .utils import normalize_text, sanitize_filename, ensure_directory_exists, get_timestamp


class TextExtractor:
    """
    Classe responsável pela extração de texto de diferentes tipos de arquivo
    """
    
    def __init__(self, reports_folder: str = "reports"):
        """
        Inicializa o extrator de texto
        
        Args:
            reports_folder: Pasta onde salvar os textos extraídos
        """
        self.reports_folder = Path(reports_folder)
        ensure_directory_exists(str(self.reports_folder))
        self.logger = logging.getLogger(__name__)
    
    def extract_text_from_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Extrai texto de um arquivo baseado em sua extensão
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Dicionário com texto extraído e metadados ou None se erro
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            self.logger.error(f"Arquivo não encontrado: {file_path}")
            return None
        
        extension = file_path.suffix.lower()
        
        try:
            if extension == '.pdf':
                return self._extract_from_pdf(file_path)
            elif extension in ['.html', '.htm']:
                return self._extract_from_html(file_path)
            elif extension in ['.txt', '.text']:
                return self._extract_from_text(file_path)
            else:
                self.logger.warning(f"Tipo de arquivo não suportado: {extension}")
                return self._extract_as_text(file_path)
                
        except Exception as e:
            self.logger.error(f"Erro ao extrair texto de {file_path}: {e}")
            return None
    
    def extract_text_from_pdf(self, pdf_path: str) -> Optional[str]:
        """
        Extrai texto de arquivo PDF
        
        Args:
            pdf_path: Caminho do arquivo PDF
            
        Returns:
            Texto extraído ou None se erro
        """
        result = self._extract_from_pdf(pdf_path)
        return result["content"] if result else None
    
    def extract_text_from_html(self, html_path: str) -> Optional[str]:
        """
        Extrai texto de arquivo HTML
        
        Args:
            html_path: Caminho do arquivo HTML
            
        Returns:
            Texto extraído ou None se erro
        """
        result = self._extract_from_html(html_path)
        return result["content"] if result else None
    
    def clean_text(self, raw_text: str) -> str:
        """
        Limpa e normaliza texto extraído
        
        Args:
            raw_text: Texto bruto
            
        Returns:
            Texto limpo e normalizado
        """
        if not raw_text:
            return ""
        
        # Normaliza o texto usando função auxiliar
        text = normalize_text(raw_text)
        
        # Remove headers/footers repetitivos comuns em PDFs
        text = self._remove_repetitive_patterns(text)
        
        # Remove linhas muito curtas que podem ser artefatos
        lines = text.split('\n')
        cleaned_lines = []
        
        for line in lines:
            line = line.strip()
            # Mantém linhas com pelo menos 10 caracteres ou que sejam números de página
            if len(line) >= 10 or re.match(r'^\d+$', line) or re.match(r'^Page \d+', line):
                cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)
    
    def save_extracted_text(self, extracted_data: Dict[str, Any], output_name: Optional[str] = None) -> Optional[str]:
        """
        Salva texto extraído em arquivo
        
        Args:
            extracted_data: Dados extraídos
            output_name: Nome do arquivo de saída (opcional)
            
        Returns:
            Caminho do arquivo salvo ou None se erro
        """
        try:
            if output_name is None:
                # Gera nome baseado no arquivo original
                original_name = Path(extracted_data["source_file"]).stem
                output_name = f"{original_name}.txt"
            
            output_name = sanitize_filename(output_name)
            output_path = self.reports_folder / output_name
            
            # Se arquivo já existe, adiciona timestamp
            if output_path.exists():
                timestamp = get_timestamp().replace(" ", "_").replace(":", "-")
                name_parts = output_name.rsplit('.', 1)
                if len(name_parts) == 2:
                    output_name = f"{name_parts[0]}_{timestamp}.{name_parts[1]}"
                else:
                    output_name = f"{output_name}_{timestamp}"
                output_path = self.reports_folder / output_name
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(extracted_data["content"])
            
            self.logger.info(f"Texto extraído salvo em: {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar texto extraído: {e}")
            return None
    
    def _extract_from_pdf(self, pdf_path: Path) -> Optional[Dict[str, Any]]:
        """
        Extrai texto de arquivo PDF usando PyPDF2
        
        Args:
            pdf_path: Caminho do arquivo PDF
            
        Returns:
            Dicionário com texto e metadados
        """
        if not PDF_AVAILABLE:
            self.logger.error("PyPDF2 não está instalado. Instale com: pip install PyPDF2")
            return None
        
        try:
            text_content = []
            metadata = {}
            
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                
                # Extrai metadados
                if pdf_reader.metadata:
                    metadata = {
                        "title": pdf_reader.metadata.get('/Title', ''),
                        "author": pdf_reader.metadata.get('/Author', ''),
                        "subject": pdf_reader.metadata.get('/Subject', ''),
                        "creator": pdf_reader.metadata.get('/Creator', ''),
                        "producer": pdf_reader.metadata.get('/Producer', ''),
                        "creation_date": str(pdf_reader.metadata.get('/CreationDate', '')),
                        "modification_date": str(pdf_reader.metadata.get('/ModDate', ''))
                    }
                
                # Extrai texto de todas as páginas
                for page_num, page in enumerate(pdf_reader.pages):
                    try:
                        page_text = page.extract_text()
                        if page_text.strip():
                            text_content.append(f"=== Página {page_num + 1} ===\n{page_text}")
                    except Exception as e:
                        self.logger.warning(f"Erro ao extrair texto da página {page_num + 1}: {e}")
                        continue
            
            full_text = '\n\n'.join(text_content)
            cleaned_text = self.clean_text(full_text)
            
            return {
                "content": cleaned_text,
                "source_file": str(pdf_path),
                "file_type": "pdf",
                "extraction_date": get_timestamp(),
                "metadata": metadata,
                "pages_count": len(pdf_reader.pages) if 'pdf_reader' in locals() else 0,
                "word_count": len(cleaned_text.split()) if cleaned_text else 0
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao processar PDF {pdf_path}: {e}")
            return None
    
    def _extract_from_html(self, html_path: Path) -> Optional[Dict[str, Any]]:
        """
        Extrai texto de arquivo HTML usando BeautifulSoup
        
        Args:
            html_path: Caminho do arquivo HTML
            
        Returns:
            Dicionário com texto e metadados
        """
        if not BS4_AVAILABLE:
            self.logger.error("BeautifulSoup4 não está instalado. Instale com: pip install beautifulsoup4")
            return None
        
        try:
            with open(html_path, 'r', encoding='utf-8', errors='ignore') as file:
                html_content = file.read()
            
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Remove scripts, estilos e outros elementos indesejados
            for element in soup(['script', 'style', 'nav', 'header', 'footer', 'aside']):
                element.decompose()
            
            # Extrai metadados
            metadata = {}
            title_tag = soup.find('title')
            if title_tag:
                metadata['title'] = title_tag.get_text().strip()
            
            # Procura por meta tags
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                name = meta.get('name') or meta.get('property')
                content = meta.get('content')
                if name and content:
                    metadata[name] = content
            
            # Extrai texto principal
            text_content = soup.get_text()
            cleaned_text = self.clean_text(text_content)
            
            return {
                "content": cleaned_text,
                "source_file": str(html_path),
                "file_type": "html",
                "extraction_date": get_timestamp(),
                "metadata": metadata,
                "word_count": len(cleaned_text.split()) if cleaned_text else 0
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao processar HTML {html_path}: {e}")
            return None
    
    def _extract_from_text(self, text_path: Path) -> Optional[Dict[str, Any]]:
        """
        Extrai texto de arquivo TXT
        
        Args:
            text_path: Caminho do arquivo TXT
            
        Returns:
            Dicionário com texto e metadados
        """
        try:
            with open(text_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
            
            cleaned_text = self.clean_text(content)
            
            return {
                "content": cleaned_text,
                "source_file": str(text_path),
                "file_type": "text",
                "extraction_date": get_timestamp(),
                "metadata": {},
                "word_count": len(cleaned_text.split()) if cleaned_text else 0
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao processar arquivo de texto {text_path}: {e}")
            return None
    
    def _extract_as_text(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Tenta extrair conteúdo como texto puro para tipos não suportados
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Dicionário com texto e metadados
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
            
            cleaned_text = self.clean_text(content)
            
            return {
                "content": cleaned_text,
                "source_file": str(file_path),
                "file_type": "unknown",
                "extraction_date": get_timestamp(),
                "metadata": {},
                "word_count": len(cleaned_text.split()) if cleaned_text else 0
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao processar arquivo {file_path}: {e}")
            return None
    
    def _remove_repetitive_patterns(self, text: str) -> str:
        """
        Remove padrões repetitivos comuns em documentos
        
        Args:
            text: Texto para limpar
            
        Returns:
            Texto sem padrões repetitivos
        """
        # Remove headers/footers repetitivos
        lines = text.split('\n')
        
        # Identifica linhas que se repetem muito (possíveis headers/footers)
        line_counts = {}
        for line in lines:
            cleaned_line = line.strip()
            if len(cleaned_line) > 5:  # Ignora linhas muito curtas
                line_counts[cleaned_line] = line_counts.get(cleaned_line, 0) + 1
        
        # Remove linhas que aparecem mais de 3 vezes
        filtered_lines = []
        for line in lines:
            cleaned_line = line.strip()
            if line_counts.get(cleaned_line, 0) <= 3 or len(cleaned_line) <= 5:
                filtered_lines.append(line)
        
        return '\n'.join(filtered_lines) 
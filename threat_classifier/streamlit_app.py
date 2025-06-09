"""
Interface web Streamlit para o Classificador de Ameaças com IA
Execute com: streamlit run streamlit_app.py
"""

import sys
from pathlib import Path

# Adiciona o diretório app ao path
sys.path.append(str(Path(__file__).parent / "app"))

# Importa e executa a interface
from app.interface import ThreatInterface

if __name__ == "__main__":
    interface = ThreatInterface()
    interface.main() 
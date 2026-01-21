import os
import sys
import json
import base64
import sqlite3
import hashlib
import time 
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Criptografia
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM 
from cryptography.exceptions import InvalidTag, InvalidKey

# UI Console
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.theme import Theme
from rich.table import Table
import inquirer

# ==============================================================================
# CONFIGURAÇÕES DE SEGURANÇA
# ==============================================================================

SCRIPT_DIR = Path(__file__).resolve().parent
KEY_FILE = SCRIPT_DIR / "masterkey.storagekey"
DB_FILE = SCRIPT_DIR / "crypto_vault.db" 

# SEGURANÇA MÁXIMA: 1 Milhão de iterações.
PBKDF2_ITERATIONS = 1_000_000 
KEY_SIZE_BYTES = 32 # AES-256

custom_theme = Theme({
    "info": "cyan", "warning": "yellow", "error": "bold red", "success": "bold green",
    "key": "bold magenta", "vault": "bold blue", "path": "dim white"
})
console = Console(theme=custom_theme)

# ==============================================================================
# 1. MOTOR DE CHAVE MESTRA
# ==============================================================================

class MasterKeyManager:
    SALT_SIZE = 16

    def __init__(self):
        self.master_key: Optional[bytes] = None

    def _derive_key_from_password(self, password_bytes: bytes, salt: bytes) -> bytes:
        console.print(f"[info]⌛ Derivando chaves ({PBKDF2_ITERATIONS} iterações)...[/info]")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=KEY_SIZE_BYTES, salt=salt,
            iterations=PBKDF2_ITERATIONS, backend=default_backend()
        )
        return kdf.derive(password_bytes)

    def load_or_create_master_key(self, password: str):
        password_bytes = password.strip().encode('utf-8')
        
        if KEY_FILE.exists():
            console.print(f"[info]🔒 Cofre de Chave encontrado. Validando...[/info]")
            try:
                with open(KEY_FILE, 'r') as f:
                    data = json.load(f)
                
                salt = base64.b64decode(data['salt'])
                nonce = base64.b64decode(data['nonce'])
                ciphertext_with_tag = base64.b64decode(data['ciphertext'])
                
                kek = self._derive_key_from_password(password_bytes, salt)
                
                aesgcm = AESGCM(kek)
                self.master_key = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
                
                console.print("[success]✅ Senha correta. Acesso liberado.[/success]")
                
            except InvalidTag:
                console.print("[error]❌ SENHA INCORRETA.[/error]")
                return False
            except Exception as e:
                console.print(f"[error]❌ ERRO CRÍTICO: {e}[/error]")
                return False
        else:
            console.print(f"[warning]🆕 Criando novo Cofre de Chave Mestra...[/warning]")
            
            self.master_key = os.urandom(KEY_SIZE_BYTES)
            salt = os.urandom(self.SALT_SIZE)
            nonce = os.urandom(12) 
            
            kek = self._derive_key_from_password(password_bytes, salt)
            
            aesgcm = AESGCM(kek)
            ciphertext_with_tag = aesgcm.encrypt(nonce, self.master_key, associated_data=None) 
            
            data = {
                'iterations': PBKDF2_ITERATIONS, 
                'salt': base64.b64encode(salt).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext_with_tag).decode('utf-8'), 
                'desc': "Chave Mestra AES-256."
            }
            with open(KEY_FILE, 'w') as f:
                json.dump(data, f, indent=4)
            console.print(f"[success]✅ {KEY_FILE.name} criado.[/success]")
        
        return True

# ==============================================================================
# 2. VAULT DE SENHAS (100% CRIPTOGRAFADO - SEM TEXTO PLANO)
# ==============================================================================

class PasswordVault:
    def __init__(self, master_key: bytes):
        self.master_key = master_key
        self.aesgcm = AESGCM(master_key) 
        
        self.conn = sqlite3.connect(DB_FILE)
        self.cursor = self.conn.cursor()
        
        self._setup_db() 
        console.print(f"[vault]🔑 DB Carregado: {DB_FILE.name} (Modo: Full Encryption)[/vault]")

    def _setup_db(self):
        """Cria a tabela onde TUDO (exceto ID) é BLOB criptografado."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_nonce BLOB NOT NULL, 
                service_ciphertext BLOB NOT NULL,
                data_nonce BLOB NOT NULL,
                data_ciphertext BLOB NOT NULL 
            )
        """)
        self.conn.commit()

    def _encrypt_field(self, data: Dict[str, str]) -> Tuple[bytes, bytes]:
        """Criptografa um dicionário para bytes."""
        nonce = os.urandom(12) 
        json_data = json.dumps(data).encode('utf-8')
        ciphertext_with_tag = self.aesgcm.encrypt(nonce, json_data, associated_data=None)
        return nonce, ciphertext_with_tag

    def _decrypt_field(self, nonce: bytes, ciphertext: bytes) -> Dict[str, str]:
        """Descriptografa bytes para dicionário."""
        decrypted_json = self.aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return json.loads(decrypted_json.decode('utf-8'))

    # --- CRUD OPERAÇÕES ---

    def add_entry(self, service_name: str, email: str, password: str) -> bool:
        # Criptografa o NOME DO SERVIÇO separadamente
        s_nonce, s_cipher = self._encrypt_field({'service_name': service_name})
        # Criptografa DADOS (Email/Senha) separadamente
        d_nonce, d_cipher = self._encrypt_field({'email': email, 'password': password})

        self.cursor.execute(
            "INSERT INTO passwords (service_nonce, service_ciphertext, data_nonce, data_ciphertext) VALUES (?, ?, ?, ?)",
            (s_nonce, s_cipher, d_nonce, d_cipher)
        )
        self.conn.commit()
        return True

    def get_all_entries(self) -> List[Dict[str, Any]]:
        # O SQL não consegue ordenar ou filtrar porque tudo é lixo binário para ele.
        # Trazemos tudo e processamos na RAM.
        self.cursor.execute("SELECT id, service_nonce, service_ciphertext, data_nonce, data_ciphertext FROM passwords")
        results = self.cursor.fetchall()
        
        decrypted_entries = []
        for row in results:
            id, s_nonce, s_cipher, d_nonce, d_cipher = row
            try:
                # Descriptografa Nome do Serviço
                service_data = self._decrypt_field(s_nonce, s_cipher)
                # Descriptografa Email/Senha
                credential_data = self._decrypt_field(d_nonce, d_cipher)
                
                decrypted_entries.append({
                    'id': id,
                    'service_name': service_data['service_name'],
                    'email': credential_data['email'],
                    'password': credential_data['password']
                })
            except InvalidTag:
                console.print(f"[error]❌ CORRUPÇÃO DETECTADA: Entrada ID {id} inválida ou adulterada.[/error]")
            
        # Ordenação feita em Python (RAM)
        return sorted(decrypted_entries, key=lambda x: x.get('service_name', '').lower())

    def get_entry_by_id(self, entry_id: int) -> Optional[Dict[str, Any]]:
        self.cursor.execute("SELECT id, service_nonce, service_ciphertext, data_nonce, data_ciphertext FROM passwords WHERE id = ?", (entry_id,))
        row = self.cursor.fetchone()
        
        if not row: return None
            
        id, s_nonce, s_cipher, d_nonce, d_cipher = row
        try:
            service_data = self._decrypt_field(s_nonce, s_cipher)
            credential_data = self._decrypt_field(d_nonce, d_cipher)
            
            return {
                'id': id,
                'service_name': service_data['service_name'],
                'email': credential_data['email'],
                'password': credential_data['password']
            }
        except InvalidTag:
            console.print("[error]❌ ERRO DE DESCRIPTOGRAFIA: Dados inválidos.[/error]")
            return None

    def update_entry(self, entry_id: int, service_name: str, email: str, password: str) -> bool:
        s_nonce, s_cipher = self._encrypt_field({'service_name': service_name})
        d_nonce, d_cipher = self._encrypt_field({'email': email, 'password': password})

        self.cursor.execute(
            "UPDATE passwords SET service_nonce=?, service_ciphertext=?, data_nonce=?, data_ciphertext=? WHERE id=?",
            (s_nonce, s_cipher, d_nonce, d_cipher, entry_id)
        )
        self.conn.commit()
        return self.cursor.rowcount > 0

    def delete_entry(self, entry_id: int) -> bool:
        self.cursor.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def close(self):
        self.conn.close()

# ==============================================================================
# 3. INTERFACE DE LINHA DE COMANDO (CLI)
# ==============================================================================

class PasswordManagerCLI:
    
    def __init__(self, master_key: bytes):
        self.vault = PasswordVault(master_key)
        self.menu_choices = [
            ('👁️ Ver Senhas', 'VIEW'),
            ('➕ Nova Senha', 'ADD'),
            ('✏️ Editar', 'EDIT'),
            ('🗑️ Deletar', 'DELETE'),
            ('🚪 Sair', 'EXIT')
        ]
        
    def run(self):
        while True:
            # Pequeno delay para evitar spam em caso de erro de input
            time.sleep(0.1)
            
            questions = [inquirer.List('action', message="Menu Principal", choices=self.menu_choices)]
            try:
                answer = inquirer.prompt(questions)
                if not answer: break
                    
                action = answer['action']

                if action == 'VIEW': self.view_passwords()
                elif action == 'ADD': self.add_password()
                elif action == 'EDIT': self.edit_password()
                elif action == 'DELETE': self.delete_password()
                elif action == 'EXIT': break
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                console.print(f"[error]Erro no Menu: {e}[/error]")

    def view_passwords(self, show_all_data=True):
        console.rule("[bold vault]👁️ VAULT[/bold vault]")
        entries = self.vault.get_all_entries()

        if not entries:
            console.print("[warning]O Vault está vazio.[/warning]")
            return

        table = Table(style="vault")
        table.add_column("ID", style="key", justify="right")
        table.add_column("Serviço", style="info")
        
        if show_all_data:
            table.add_column("Usuário/Email", style="white")
            table.add_column("Senha", style="white")

        for entry in entries:
            pwd = entry['password'] if show_all_data else "******"
            table.add_row(str(entry['id']), entry['service_name'], entry['email'], pwd)
        
        console.print(table)
        if not show_all_data: console.print("\n[info]Use EDITAR para ver detalhes.[/info]")

    def add_password(self):
        console.rule("[bold vault]➕ NOVO[/bold vault]")
        
        service = Prompt.ask("Serviço")
        email = Prompt.ask("Usuario/Email")
        password = Prompt.ask("Senha", password=True)
        
        if self.vault.add_entry(service, email, password):
            console.print(f"\n[success]✅ Salvo e Criptografado![/success]")
        else:
            console.print("[error]❌ Erro ao salvar.[/error]")

    def select_entry_id(self, action):
        self.view_passwords(show_all_data=False)
        entries = self.vault.get_all_entries()
        if not entries: return None

        choices = [(f"[{e['id']}] {e['service_name']}", e['id']) for e in entries]
        q = [inquirer.List('id', message=f"Selecione para {action}", choices=choices)]
        ans = inquirer.prompt(q)
        return ans['id'] if ans else None

    def edit_password(self):
        eid = self.select_entry_id("EDITAR")
        if not eid: return

        entry = self.vault.get_entry_by_id(eid)
        if not entry:
            console.print(f"[error]ID {eid} inválido.[/error]")
            return

        console.rule(f"[bold vault]✏️ EDITANDO: {entry['service_name']}[/bold vault]")
        
        ns = Prompt.ask("Serviço", default=entry['service_name'])
        ne = Prompt.ask("Email", default=entry['email'])
        
        console.print(f"[info]Senha Atual (Memória): [key]{entry['password']}[/key][/info]")
        np = Prompt.ask("Nova Senha (Enter para manter)", password=True, default="")
        if np == "": np = entry['password']
        
        if self.vault.update_entry(eid, ns, ne, np):
            console.print(f"\n[success]✅ Atualizado e Re-Criptografado![/success]")

    def delete_password(self):
        eid = self.select_entry_id("DELETAR")
        if not eid: return

        entry = self.vault.get_entry_by_id(eid)
        if not entry: return

        console.print(f"[warning]Vai deletar:[/warning] [key]{entry['service_name']}[/key]")
        if Prompt.ask("Confirmar?", choices=["s", "n"]) == "s":
            if self.vault.delete_entry(eid):
                console.print(f"\n[success]🗑️ Deletado.[/success]")

# ==============================================================================
# MAIN
# ==============================================================================

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print(Panel.fit("[bold white on blue] 🔑 KEY-PASSWORD MANAGER (V3.0 - FULL ENCRYPTED) [/bold white on blue]", border_style="blue"))
    
    km = MasterKeyManager()
    
    while True:
        pwd = Prompt.ask("🔑 Senha Mestra", password=True)
        if not pwd.strip(): continue
            
        if km.load_or_create_master_key(pwd):
            break
        
        console.print("[error]Acesso Negado. Aguarde...[/error]")
        time.sleep(2) # Anti-brute force delay
        
        if not KEY_FILE.exists(): break

    if km.master_key:
        cli = None
        try:
            cli = PasswordManagerCLI(km.master_key)
            cli.run()
        except Exception as e:
            console.print(Panel(f"[bold red]ERRO FATAL: {e}[/bold red]"))
        finally:
            if cli and hasattr(cli, 'vault'):
                cli.vault.close()
    
    console.print("\n[bold magenta]*** FIM ***[/bold magenta]")
    input("Enter para fechar...")

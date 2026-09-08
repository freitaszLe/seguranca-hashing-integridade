#!/usr/bin/env python3
"""
Item 2.3 - Implementação de Salt e Validação de Senha
Autores: Leticia Arruda de Freitas e Anthony Gabriel Oliveira Cruz
Disciplina: Segurança em Sistemas Computacionais - IFMT

Este script simula um módulo de cadastro e autenticação de usuários
utilizando hashing SHA-256 com salt aleatório criptograficamente seguro.

Uso:
    python cadastro_verificacao.py --cadastrar <usuario> <senha>
    python cadastro_verificacao.py --verificar <usuario> <senha>
"""

import hashlib
import os
import sys

# Arquivo onde os registros de usuários são armazenados
ARQUIVO_USUARIOS = "usuarios.txt"

# Tamanho do salt em bytes (16 bytes = 128 bits de entropia)
TAMANHO_SALT = 16


def gerar_salt():
    """
    Gera um salt aleatório criptograficamente seguro.

    Utiliza os.urandom() que acessa o gerador de números aleatórios
    do sistema operacional (/dev/urandom no Linux), garantindo
    imprevisibilidade adequada para uso criptográfico.

    Returns:
        Bytes aleatórios de tamanho TAMANHO_SALT (16 bytes).
    """
    return os.urandom(TAMANHO_SALT)


def calcular_hash_com_salt(salt_bytes, senha):
    """
    Calcula SHA-256 da concatenação salt + senha.

    O salt é concatenado ANTES da senha (prefixo) para evitar
    ataques de extensão de comprimento (length extension attacks).
    A senha é convertida de string para bytes usando UTF-8.

    Args:
        salt_bytes: Salt em bytes.
        senha: Senha em texto claro (string).

    Returns:
        String hexadecimal do hash SHA-256(salt + senha).
    """
    # Converte a senha para bytes (UTF-8) e concatena com o salt
    dados = salt_bytes + senha.encode('utf-8')
    return hashlib.sha256(dados).hexdigest()


def cadastrar_usuario(usuario, senha):
    """
    Cadastra um novo usuário com senha protegida por salt + hash.

    Fluxo:
    1. Verifica se o usuário já existe
    2. Gera salt aleatório de 16 bytes
    3. Calcula SHA-256(salt + senha)
    4. Salva no formato: usuario:salt_hex:hash_hex

    A senha NUNCA é armazenada em texto claro.

    Args:
        usuario: Nome de usuário.
        senha: Senha em texto claro.
    """
    # Verifica duplicata
    if os.path.exists(ARQUIVO_USUARIOS):
        with open(ARQUIVO_USUARIOS, 'r', encoding='utf-8') as f:
            for linha in f:
                partes = linha.strip().split(':')
                if len(partes) >= 1 and partes[0] == usuario:
                    print(f"[ERRO] Usuário '{usuario}' já cadastrado.")
                    return

    # Gera salt criptograficamente seguro
    salt_bytes = gerar_salt()
    salt_hex = salt_bytes.hex()

    # Calcula o hash com salt
    hash_hex = calcular_hash_com_salt(salt_bytes, senha)

    # Salva no arquivo no formato especificado
    with open(ARQUIVO_USUARIOS, 'a', encoding='utf-8') as f:
        f.write(f"{usuario}:{salt_hex}:{hash_hex}\n")

    print(f"[SUCESSO] Usuário '{usuario}' cadastrado com sucesso.")
    print(f"  Salt (hex): {salt_hex}")
    print(f"  Hash (hex): {hash_hex}")


def verificar_usuario(usuario, senha):
    """
    Verifica as credenciais de um usuário.

    Fluxo:
    1. Localiza o registro do usuário em usuarios.txt
    2. Extrai o salt armazenado (converte de hex para bytes)
    3. Recalcula SHA-256(salt + senha_digitada)
    4. Compara o hash calculado com o hash armazenado

    A comparação é feita entre os hashes, nunca entre senhas em texto claro.

    Args:
        usuario: Nome de usuário.
        senha: Senha fornecida para verificação.
    """
    if not os.path.exists(ARQUIVO_USUARIOS):
        print("Acesso negado")
        print("  [INFO] Nenhum usuário cadastrado.")
        return

    # Busca o registro do usuário
    registro_encontrado = None
    with open(ARQUIVO_USUARIOS, 'r', encoding='utf-8') as f:
        for linha in f:
            linha = linha.strip()
            if not linha:
                continue
            partes = linha.split(':')
            if len(partes) == 3 and partes[0] == usuario:
                registro_encontrado = partes
                break

    if registro_encontrado is None:
        print("Acesso negado")
        print(f"  [INFO] Usuário '{usuario}' não encontrado.")
        return

    _, salt_hex, hash_armazenado = registro_encontrado

    # Recupera o salt original convertendo de hexadecimal para bytes
    salt_bytes = bytes.fromhex(salt_hex)

    # Recalcula o hash com o salt armazenado e a senha fornecida
    hash_calculado = calcular_hash_com_salt(salt_bytes, senha)

    # Comparação segura dos hashes
    if hash_calculado == hash_armazenado:
        print("Acesso permitido")
        print(f"  [INFO] Usuário '{usuario}' autenticado com sucesso.")
    else:
        print("Acesso negado")
        print(f"  [INFO] Senha incorreta para '{usuario}'.")


def main():
    """Ponto de entrada principal."""
    if len(sys.argv) != 4:
        print("Uso:")
        print("  python cadastro_verificacao.py --cadastrar <usuario> <senha>")
        print("  python cadastro_verificacao.py --verificar <usuario> <senha>")
        sys.exit(1)

    modo = sys.argv[1]
    usuario = sys.argv[2]
    senha = sys.argv[3]

    if modo == '--cadastrar':
        cadastrar_usuario(usuario, senha)
    elif modo == '--verificar':
        verificar_usuario(usuario, senha)
    else:
        print(f"[ERRO] Modo '{modo}' não reconhecido. Use --cadastrar ou --verificar.")
        sys.exit(1)


if __name__ == '__main__':
    main()

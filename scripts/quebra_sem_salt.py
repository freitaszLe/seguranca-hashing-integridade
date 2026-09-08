#!/usr/bin/env python3
"""
Item 2.2 - Detector de Senhas Fracas com Hash sem Salt
Autores: Leticia Arruda de Freitas e Anthony Gabriel Oliveira Cruz
Disciplina: Segurança em Sistemas Computacionais - IFMT

Este script realiza um ataque de dicionário contra hashes SHA-256 sem salt.
Demonstra a vulnerabilidade de armazenar senhas hasheadas sem proteção adicional.

Uso:
    python quebra_sem_salt.py hashes_sem_salt.txt senhas_comuns.txt
"""

import hashlib
import sys
import time


def carregar_arquivo_linhas(caminho):
    """
    Carrega um arquivo texto e retorna lista de linhas (sem espaços extras).

    Args:
        caminho: Caminho do arquivo a ser lido.

    Returns:
        Lista de strings, uma por linha do arquivo.
    """
    linhas = []
    with open(caminho, 'r', encoding='utf-8') as f:
        for linha in f:
            linha_limpa = linha.strip()
            if linha_limpa:
                linhas.append(linha_limpa)
    return linhas


def gerar_hash_sha256(texto):
    """
    Gera o hash SHA-256 de uma string de texto.

    A string é convertida para bytes usando UTF-8 antes do cálculo,
    garantindo compatibilidade com caracteres especiais.

    Args:
        texto: String a ser hasheada.

    Returns:
        String hexadecimal do hash SHA-256.
    """
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()


def construir_dicionario_hashes(senhas):
    """
    Pré-computa os hashes de todas as senhas do dicionário.

    Estratégia de otimização: ao invés de calcular o hash de cada senha
    para cada hash alvo (O(n*m)), construímos um dicionário invertido
    hash->senha (O(n+m)). Isso transforma a busca em O(1) por hash alvo.

    Args:
        senhas: Lista de senhas do dicionário.

    Returns:
        Dicionário {hash_sha256: senha_original}.
    """
    tabela = {}
    for senha in senhas:
        hash_hex = gerar_hash_sha256(senha)
        tabela[hash_hex] = senha
    return tabela


def quebrar_hashes(arquivo_hashes, arquivo_senhas):
    """
    Executa o ataque de dicionário contra hashes sem salt.

    Fluxo:
    1. Carrega o dicionário de senhas comuns
    2. Pré-computa os hashes de todas as senhas (tabela invertida)
    3. Para cada hash alvo, busca correspondência na tabela
    4. Exibe resultados e estatísticas de tempo

    Args:
        arquivo_hashes: Caminho do arquivo com hashes alvo (um por linha).
        arquivo_senhas: Caminho do dicionário de senhas comuns.
    """
    # Carrega dados
    hashes_alvo = carregar_arquivo_linhas(arquivo_hashes)
    senhas = carregar_arquivo_linhas(arquivo_senhas)

    print(f"[INFO] {len(hashes_alvo)} hash(es) alvo carregado(s)")
    print(f"[INFO] {len(senhas)} senha(s) no dicionário")
    print("-" * 70)

    # Mede o tempo total do ataque
    inicio = time.time()

    # Pré-computa a tabela hash -> senha
    # Essa abordagem é eficiente pois cada senha é hasheada uma única vez
    tabela_hashes = construir_dicionario_hashes(senhas)

    tempo_precomputacao = time.time() - inicio
    print(f"[INFO] Pré-computação do dicionário: {tempo_precomputacao:.4f}s")
    print("-" * 70)

    # Busca correspondências
    encontradas = 0
    inicio_busca = time.time()

    for hash_alvo in hashes_alvo:
        hash_alvo_lower = hash_alvo.lower()

        if hash_alvo_lower in tabela_hashes:
            senha = tabela_hashes[hash_alvo_lower]
            print(f"{hash_alvo}:{senha}")
            encontradas += 1
        else:
            print(f"{hash_alvo}:NAO_ENCONTRADA")

    tempo_busca = time.time() - inicio_busca
    tempo_total = time.time() - inicio

    # Estatísticas
    print("-" * 70)
    print(f"[RESULTADO] {encontradas}/{len(hashes_alvo)} senha(s) quebrada(s)")
    print(f"[TEMPO] Pré-computação: {tempo_precomputacao:.4f}s")
    print(f"[TEMPO] Busca: {tempo_busca:.6f}s")
    print(f"[TEMPO] Total: {tempo_total:.4f}s")
    if len(hashes_alvo) > 0:
        print(f"[TEMPO] Média por hash: {tempo_total/len(hashes_alvo):.6f}s")


def main():
    """Ponto de entrada principal."""
    if len(sys.argv) != 3:
        print("Uso: python quebra_sem_salt.py <hashes_sem_salt.txt> <senhas_comuns.txt>")
        sys.exit(1)

    arquivo_hashes = sys.argv[1]
    arquivo_senhas = sys.argv[2]

    quebrar_hashes(arquivo_hashes, arquivo_senhas)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Parte 4 (Bônus) - Detector de Colisões em Funções Hash
Autores: Leticia Arruda de Freitas e Anthony Gabriel Oliveira Cruz
Disciplina: Segurança em Sistemas Computacionais - IFMT

Este script gera 1.000.000 de strings aleatórias, calcula seus hashes
usando SHA-1 e SHA-256, e verifica a ocorrência de colisões em cada algoritmo.

Uso:
    python detector_colisao.py
"""

import hashlib
import os
import time


def gerar_strings_aleatorias(quantidade, tamanho_bytes=10):
    """
    Gera uma lista de strings aleatórias usando os.urandom().

    Cada string é gerada como uma sequência de bytes aleatórios,
    garantindo distribuição uniforme e imprevisibilidade.

    Args:
        quantidade: Número de strings a gerar.
        tamanho_bytes: Tamanho de cada string em bytes (padrão: 10).

    Returns:
        Lista de bytes objects aleatórios.
    """
    print(f"[INFO] Gerando {quantidade:,} strings aleatórias de {tamanho_bytes} bytes...")
    strings = []
    for _ in range(quantidade):
        strings.append(os.urandom(tamanho_bytes))
    return strings


def testar_colisoes(strings, algoritmo):
    """
    Testa a ocorrência de colisões para um dado algoritmo de hash.

    Uma colisão ocorre quando duas entradas diferentes produzem
    o mesmo hash de saída. Este teste verifica empiricamente a
    resistência a colisões do algoritmo.

    Args:
        strings: Lista de bytes objects para hashear.
        algoritmo: Nome do algoritmo ('sha1' ou 'sha256').

    Returns:
        Tupla (numero_colisoes, tempo_execucao).
    """
    print(f"\n[TESTE] Algoritmo: {algoritmo.upper()}")
    print(f"  Testando {len(strings):,} strings...")

    inicio = time.time()

    # Dicionário que mapeia hash -> primeira string que produziu esse hash
    hashes_vistos = {}
    colisoes = 0

    for dados in strings:
        # Calcula o hash da string atual
        if algoritmo == 'sha1':
            hash_hex = hashlib.sha1(dados).hexdigest()
        elif algoritmo == 'sha256':
            hash_hex = hashlib.sha256(dados).hexdigest()
        else:
            raise ValueError(f"Algoritmo desconhecido: {algoritmo}")

        # Verifica se este hash já foi visto (colisão)
        if hash_hex in hashes_vistos:
            # Confirma que as entradas são realmente diferentes
            if hashes_vistos[hash_hex] != dados:
                colisoes += 1
                if colisoes <= 5:  # Exibe até 5 colisões como exemplo
                    print(f"  ⚠ COLISÃO ENCONTRADA!")
                    print(f"    String 1: {hashes_vistos[hash_hex].hex()}")
                    print(f"    String 2: {dados.hex()}")
                    print(f"    Hash:     {hash_hex}")
        else:
            hashes_vistos[hash_hex] = dados

    tempo = time.time() - inicio

    print(f"  Hashes únicos gerados: {len(hashes_vistos):,}")
    print(f"  Colisões encontradas: {colisoes}")
    print(f"  Tempo de execução: {tempo:.2f}s")

    return colisoes, tempo


def main():
    """Ponto de entrada principal."""
    QUANTIDADE = 1_000_000

    print("=" * 60)
    print("    DETECTOR DE COLISÕES EM FUNÇÕES HASH")
    print("=" * 60)

    # Gera as strings aleatórias (mesmas para ambos os testes)
    strings = gerar_strings_aleatorias(QUANTIDADE)

    # Teste com SHA-1
    colisoes_sha1, tempo_sha1 = testar_colisoes(strings, 'sha1')

    # Teste com SHA-256
    colisoes_sha256, tempo_sha256 = testar_colisoes(strings, 'sha256')

    # Relatório comparativo
    print("\n" + "=" * 60)
    print("    RELATÓRIO COMPARATIVO")
    print("=" * 60)
    print(f"  {'Métrica':<30} {'SHA-1':>12} {'SHA-256':>12}")
    print(f"  {'-'*30} {'-'*12} {'-'*12}")
    print(f"  {'Tamanho do digest (bits)':<30} {'160':>12} {'256':>12}")
    print(f"  {'Espaço de hashes':<30} {'2^160':>12} {'2^256':>12}")
    print(f"  {'Colisões encontradas':<30} {colisoes_sha1:>12} {colisoes_sha256:>12}")
    print(f"  {'Tempo (segundos)':<30} {tempo_sha1:>12.2f} {tempo_sha256:>12.2f}")
    print("=" * 60)

    # Análise
    print("\n[ANÁLISE]")
    if colisoes_sha1 == 0 and colisoes_sha256 == 0:
        print("  Nenhuma colisão foi encontrada em nenhum dos algoritmos.")
        print("  Isso é esperado: com 1.000.000 de strings e espaços de hash")
        print("  de 2^160 (SHA-1) e 2^256 (SHA-256), a probabilidade de")
        print("  colisão aleatória é astronomicamente baixa.")
        print()
        print("  Pelo Paradoxo do Aniversário:")
        print("  - SHA-1: ~2^80 hashes para 50% de chance de colisão")
        print("  - SHA-256: ~2^128 hashes para 50% de chance de colisão")
        print("  - Nosso teste: apenas 10^6 ≈ 2^20 hashes")

    print()
    print("  O SHA-256 é preferível ao SHA-1 porque:")
    print("  1. SHA-1 teve colisões CONSTRUÍDAS (ataque SHAttered, 2017)")
    print("  2. SHA-256 possui espaço de hash 2^96 vezes maior")
    print("  3. SHA-256 não possui ataques práticos conhecidos")
    print("  4. A margem de segurança do SHA-256 é muito superior")


if __name__ == '__main__':
    main()

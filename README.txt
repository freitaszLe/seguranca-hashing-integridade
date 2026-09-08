
# Atividade Prática 1 — Segurança em Sistemas Computacionais
## Fundamentos de Hashing e Integridade de Dados

**Autores:** Leticia Arruda de Freitas e Anthony Gabriel Oliveira Cruz
**Disciplina:** Segurança em Sistemas Computacionais
**Instituição:** IFMT — Campus Cuiabá

---

## 📁 Estrutura do Repositório

```
.
├── Relatorio_Tecnico_Hashing.pdf   # Relatório técnico completo
├── Apresentacao_Hashing.pptx       # Apresentação do trabalho
├── README.md
└── scripts/
    ├── verificador_integridade.py  # Item 2.1
    ├── quebra_sem_salt.py          # Item 2.2
    ├── cadastro_verificacao.py     # Item 2.3
    ├── quebra_com_salt.py          # Item 2.4
    ├── detector_colisao.py         # Parte 4 (Bônus)
    ├── senhas_comuns.txt           # Dicionário de senhas comuns
    ├── hashes_sem_salt.txt         # Hashes alvo (sem salt)
    └── hashes_com_salt.txt         # Hashes alvo (com salt)
```

## ⚙️ Requisitos

- Python 3.8 ou superior (sem dependências externas — usa apenas `hashlib`, `os`, `sys`, `time`)

Verifique sua versão:
```bash
python3 --version
```

## 🚀 Como testar — passo a passo

Clone o repositório e entre na pasta de scripts:
```bash
git clone https://github.com/freitaszLe/seguranca-hashing-integridade.git
cd seguranca-hashing-integridade/scripts
```

### 1️⃣ Verificador de Integridade de Arquivos

Cria um diretório de teste com alguns arquivos:
```bash
mkdir -p dados/subpasta
echo "documento de teste" > dados/arquivo.txt
echo "configuracao interna" > dados/subpasta/config.txt
```

Gera os hashes de referência (primeira execução):
```bash
python3 verificador_integridade.py dados
```
> Cria o arquivo `hashes.txt` com o SHA-256 de cada arquivo encontrado.

Simule uma adulteração e depois verifique:
```bash
echo "TEXTO ADULTERADO" >> dados/arquivo.txt
python3 verificador_integridade.py dados --verificar
```
> Classifica os arquivos em **Inalterados**, **Modificados**, **Novos** e **Removidos**.

---

### 2️⃣ Quebra de Senhas — Hash SEM Salt

```bash
python3 quebra_sem_salt.py hashes_sem_salt.txt senhas_comuns.txt
```
> Compara cada hash do arquivo contra o dicionário de senhas comuns e exibe `hash:senha_encontrada` ou `hash:NAO_ENCONTRADA`.

---

### 3️⃣ Cadastro e Verificação de Senha (com Salt)

Cadastre um usuário:
```bash
python3 cadastro_verificacao.py --cadastrar usuario1 minhasenha
```
> Gera um salt aleatório de 16 bytes, calcula SHA-256(salt + senha) e salva em `usuarios.txt`.

Teste a autenticação com a senha correta:
```bash
python3 cadastro_verificacao.py --verificar usuario1 minhasenha
```
> Deve exibir **"Acesso permitido"**.

Teste com a senha errada:
```bash
python3 cadastro_verificacao.py --verificar usuario1 senhaerrada
```
> Deve exibir **"Acesso negado"**.

---

### 4️⃣ Quebra de Senhas — Hash COM Salt

```bash
python3 quebra_com_salt.py hashes_com_salt.txt senhas_comuns.txt
```
> Extrai o salt e o hash de cada linha, testa cada senha do dicionário e exibe `salt:hash -> senha` ou `salt:hash -> NAO_ENCONTRADA`. Inclui otimização para salts reutilizados (pré-computação por salt único).

---

### 5️⃣ Detector de Colisões (Bônus)

```bash
python3 detector_colisao.py
```
> Gera 1.000.000 de strings aleatórias, calcula os hashes com **SHA-1** e **SHA-256**, e reporta o número de colisões encontradas em cada algoritmo (execução leva alguns segundos).

---

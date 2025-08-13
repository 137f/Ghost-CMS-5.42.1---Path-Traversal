# Ghost CMS Path Traversal Exploit – CVE-2023-32235

## 📌 Descrição
Este exploit automatiza a exploração da vulnerabilidade **Path Traversal** no **Ghost CMS** (versões anteriores à 5.42.1), permitindo a leitura de arquivos arbitrários dentro da pasta do tema ativo via endpoint `/assets/built/`.  
Essa falha pode expor arquivos sensíveis, como `.env`, `config.production.json` e `package.json`.

**CVSS Score:** 7.5 (High)  
**Impactos possíveis:**
- Vazamento de credenciais e segredos
- Exposição de configuração do servidor
- Auxílio para ataques posteriores (LFI → RCE)

---

## ⚙️ Requisitos
- Python 3.8 ou superior
- Biblioteca `requests` instalada  
```bash
pip install requests>=2.28.1
```

Contact
------------
Caso queira me contatar ou precise de algum serviço, me encontre nas seguintes plataformas:

Discord User: 4wj.

Instargram: @glowwz9

Email: vliyanie1337@proton.me

import shodan
import requests
import json
import csv
import logging
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import time 

# Sistema de logs
logging.basicConfig(
    filename="osint_tool.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Insira as api_keys do shodan e do virus total
SHODAN_API_KEY = "suakey" 
VIRUSTOTAL_API_KEY = "suakey" 

# Funções de consulta
def consultar_shodan(ip):
    global shodan_reqs_restantes
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        
        # Obtenção das informações de limite de requisição
        info = api.info()
        shodan_reqs_restantes = info.get('requests_remaining', 'N/A')  # Ajuste aqui

        resultado = api.host(ip)
        return {
            "API": "Shodan",
            "IP": resultado['ip_str'],
            "Organizacao": resultado.get('org', 'N/A'),
            "SO": resultado.get('os', 'N/A'),
            "Portas": [item['port'] for item in resultado['data']],
            "Servicos": [item.get('product', 'N/A') for item in resultado['data']],
            "Hostnames": resultado.get('hostnames', []),
            "ASN": resultado.get('asn', 'N/A'),
            "Pais": resultado.get('country_name', 'N/A'),
            "Vulnerabilidades": resultado.get('vulns', []),
        }
    except Exception as e:
        logging.error(f"Erro ao consultar Shodan: {e}")
        return {"API": "Shodan", "Erro": str(e)}

def consultar_ipinfo(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url)
        data = response.json()
        return {
            "API": "IPInfo",
            "IP": data.get("ip"),
            "ASN": data.get("asn", {}).get("asn", 'N/A'),
            "Cidade": data.get("city", 'N/A'),
            "Regiao": data.get("region", 'N/A'),
            "Pais": data.get("country", 'N/A'),
            "Localizacao": data.get("loc", 'N/A'),  
            "Organizacao": data.get("org", 'N/A'),
            "Hostname": data.get("hostname", 'N/A'),
        }
    except Exception as e:
        logging.error(f"Erro ao consultar IPInfo: {e}")
        return {"API": "IPInfo", "Erro": str(e)}

def consultar_virustotal(ip):
    global virustotal_reqs_restantes
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)

        virustotal_reqs_restantes = response.headers.get('x-ratelimit-remaining', 'N/A')
        
        data = response.json()
        if 'data' not in data:
            return {"API": "VirusTotal", "IP": ip, "Erro": "IP não encontrado"}

        resultado = data['data'][0]
        return {
            "API": "VirusTotal",
            "IP": resultado['id'],
            "Deteccao": resultado['attributes'].get('last_analysis_stats', {}),
            "Reputacao": resultado['attributes'].get('reputation', 'N/A'),
            "Primeira Observacao": resultado['attributes'].get('first_submission_date', 'N/A'),
            "Ultima Observacao": resultado['attributes'].get('last_submission_date', 'N/A'),
            "Historico de Malware": [item.get('engine_name', 'N/A') for item in resultado['attributes'].get('last_analysis_results', {}).values()],
        }
    except Exception as e:
        logging.error(f"Erro ao consultar VirusTotal: {e}")
        return {"API": "VirusTotal", "Erro": str(e)}

# Função para combinar resultados de todas as APIs
def combinar_resultados(ip):
    time.sleep(1)  # Pausa de 1 segundo entre as requisições para não exceder o limite da API do Shodan
    shodan_resultado = consultar_shodan(ip)
    
    time.sleep(1)  # Pausa de 1 segundo entre as requisições para não exceder o limite da API do IPInfo
    ipinfo_resultado = consultar_ipinfo(ip)
    
    time.sleep(1)  # Pausa de 1 segundo entre as requisições para não exceder o limite da API do VirusTotal
    virustotal_resultado = consultar_virustotal(ip)

    resultados = {
        "IP": ip,
        "Organizacao": shodan_resultado.get("Organizacao") or ipinfo_resultado.get("Organizacao"),
        "Pais": shodan_resultado.get("Pais") or ipinfo_resultado.get("Pais"),
        "Cidade": ipinfo_resultado.get("Cidade"),
        "Regiao": ipinfo_resultado.get("Regiao"),
        "Localizacao": ipinfo_resultado.get("Localizacao"),
        "SO": shodan_resultado.get("SO"),
        "ASN": shodan_resultado.get("ASN") or ipinfo_resultado.get("ASN"),
        "Hostnames": list(set(shodan_resultado.get("Hostnames", []) + ipinfo_resultado.get("Hostnames", []))),
        "Portas": list(set(shodan_resultado.get("Portas", []))),
        "Servicos": list(set(shodan_resultado.get("Servicos", []))),
        "Vulnerabilidades": list(set(shodan_resultado.get("Vulnerabilidades", []))),
        "Deteccao VirusTotal": virustotal_resultado.get("Deteccao"),
        "Reputacao VirusTotal": virustotal_resultado.get("Reputacao"),
        "Historico de Malware VirusTotal": list(set(virustotal_resultado.get("Historico de Malware", []))),
    }

    return resultados

# Funções para salvar os resultados
def salvar_em_json(resultados, arquivo="resultados.json"):
    try:
        with open(arquivo, "w") as f:
            json.dump(resultados, f, indent=4)
        print(f"Resultados salvos como JSON em: {arquivo}")
    except Exception as e:
        print(f"Erro ao salvar JSON: {e}")

def salvar_em_csv(resultados, arquivo="resultados.csv"):
    try:
        with open(arquivo, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Campo", "Valor"])
            for chave, valor in resultados.items():
                if isinstance(valor, list):
                    valor = ', '.join(map(str, valor))  # Para listar as portas ou vulnerabilidades
                writer.writerow([chave, valor])
        print(f"Resultados salvos como CSV em: {arquivo}")
    except Exception as e:
        print(f"Erro ao salvar CSV: {e}")

# Função para consultar e exibir os resultados na interface
def consultar_e_exibir():
    ip = ip_entry.get()
    if not ip:
        messagebox.showerror("Erro", "Por favor, insira um IP ou domínio.")
        return

    mostrar_progresso() 

    resultados = combinar_resultados(ip)
    texto_resultado = f"Resultados para o IP: {resultados['IP']}\n"
    
    # Exibir quantas requisições restam para o Shodan e VirusTotal
    texto_resultado += f"\nConsultas restantes (Shodan): {shodan_reqs_restantes}\n"
    texto_resultado += f"Consultas restantes (VirusTotal): {virustotal_reqs_restantes}\n"
    
    for chave, valor in resultados.items():
        if isinstance(valor, list):
            valor = ', '.join(map(str, valor))  # Para listar portas e vulnerabilidades
        texto_resultado += f"{chave}: {valor}\n"

    resultado_text.delete("1.0", tk.END)
    resultado_text.insert(tk.END, texto_resultado)

# Função para salvar os resultados
def salvar():
    ip = ip_entry.get()
    if not ip:
        messagebox.showerror("Erro", "Por favor, insira um IP ou domínio.")
        return

    resultados = combinar_resultados(ip)
    escolha = format_entry.get().strip().lower()

    if escolha == "json":
        salvar_em_json(resultados)
    elif escolha == "csv":
        salvar_em_csv(resultados)
    else:
        messagebox.showinfo("Informação", "Escolha um formato válido para salvar (json ou csv).")

# Função para exibir a barra de progresso
def mostrar_progresso():
    barra = ttk.Progressbar(janela, orient="horizontal", length=200, mode="indeterminate")
    barra.pack(pady=10)
    barra.start()

    janela.after(5000, lambda: barra.stop())  
    janela.after(5000, lambda: barra.pack_forget())  

# Interface gráfica
janela = tk.Tk()
janela.title("Ferramenta OSINT")
janela.geometry("600x600")
janela.configure(bg="black")  

# Estilo para widgets
label_style = {
    "bg": "black", 
    "fg": "white",  
    "font": ("Arial", 12)
}

entry_style = {
    "bg": "gray20", 
    "fg": "white",  
    "insertbackground": "white", 
    "font": ("Arial", 12)
}

button_style = {
    "bg": "gray25",
    "fg": "white",
    "font": ("Arial", 12)
}

text_style = {
    "bg": "gray20",  
    "fg": "white",  
    "font": ("Arial", 12)
}

# Campos para inserir o IP e formato de salvamento
ip_label = tk.Label(janela, text="Insira o IP ou domínio:", **label_style)
ip_label.pack(pady=5)

ip_entry = tk.Entry(janela, width=40, **entry_style)
ip_entry.pack(pady=5)

format_label = tk.Label(janela, text="Formato para salvar (json/csv):", **label_style)
format_label.pack(pady=5)

format_entry = tk.Entry(janela, width=20, **entry_style)
format_entry.pack(pady=5)

# Botões para consulta e salvar
consultar_button = tk.Button(janela, text="Consultar", command=consultar_e_exibir, **button_style)
consultar_button.pack(pady=10)

salvar_button = tk.Button(janela, text="Salvar", command=salvar, **button_style)
salvar_button.pack(pady=10)

# Exibição dos resultados
resultado_text = tk.Text(janela, width=70, height=20, **text_style)
resultado_text.pack(pady=20)

janela.mainloop()
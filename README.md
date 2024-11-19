Desenvolvi uma ferramenta de OSINT, para buscar informações como o 
        IP
        Organizacao
        Pais
        Cidade
        Regiao
        Localizacao
        SO
        ASN
        Hostnames
        Portas
        Servicos
        Vulnerabilidades
        Deteccao VirusTotal
        Reputacao VirusTotal
        Historico de Malware VirusTotal
Essa ferramenta foi desenvolvida em Python, e utiliza as api's do shodan, do virustotal e do ipinfo, para se complementarem
e extrair o melhor das 3 api's em uma ferramenta só, otimizando o tempo gasto para consulta

Fiz algumas melhorias, colocando uma barra de progresso para buscas mais longas, um método de exportação do relatorio
tanto para JSON quanto para CSV. Coloquei também um sistema de logs para avaliar quando foram feitas as buscas
através da ferramenta.

Utilizei o tkinter para fazer uma interface gráfica básica, para otimizar o uso da ferramenta.

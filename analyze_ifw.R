# Verifica e instala a biblioteca 'tidyverse' (conjunto de pacotes para manipulação e visualização de dados)
if (!require("tidyverse")) install.packages("tidyverse", repos = "http://cran.us.r-project.org")
# Verifica e instala a biblioteca 'lubridate' (especializada em manipulação de datas e horas)
if (!require("lubridate")) install.packages("lubridate", repos = "http://cran.us.r-project.org")
# Verifica e instala a biblioteca 'ggrepel' (evita que os rótulos de texto se sobreponham nos gráficos)
if (!require("ggrepel")) install.packages("ggrepel", repos = "http://cran.us.r-project.org")
# Verifica e instala a biblioteca 'scales' (ajuda na formatação de eixos e legendas de gráficos)
if (!require("scales")) install.packages("scales", repos = "http://cran.us.r-project.org")

# Carrega as bibliotecas no ambiente de execução
library(tidyverse)
library(lubridate)
library(ggrepel)
library(scales)

# Carregamento e Limpeza de Dados
cat("Carregando e limpando dados do arquivo IFW.csv...\n")
df <- read.csv("IFW.csv", check.names = FALSE) # empedi alteracao de coluna com caracter expecial

# garantir a consistência dos dados
col_names <- c("resp_pkts", "service", "orig_ip_bytes", "local_resp", "missed_bytes",
               "protocol", "duration", "conn_state", "dest_ip", "orig_pkts",
               "community_id", "resp_ip_bytes", "dest_port", "orig_bytes",
               "local_orig", "datetime", "history", "resp_bytes", "uid",
               "src_port", "ts", "src_ip", "mitre_attack_tactics")

# Se o número de colunas no arquivo bater com a lista, renomeia as colunas do dataframe
if (ncol(df) == length(col_names)) {
  colnames(df) <- col_names
}

df <- df %>%  # tranfomacao dos dados usados
  mutate(
    # Converte a coluna datetime para o formato de data/hora do R (POSIXct) no fuso UTC
    datetime = as.POSIXct(datetime, format="%Y-%m-%dT%H:%M:%OSZ", tz="UTC"),
    # Converte colunas de bytes e duração para o tipo numérico para permitir cálculos matemáticos
    across(c(orig_bytes, resp_bytes, orig_ip_bytes, resp_ip_bytes, duration), as.numeric)
  ) %>%
  # Remove linhas onde a data está ausente (valores NA)
  filter(!is.na(datetime))

dir.create("analise_graficos", showWarnings = FALSE) # criar diretorio se ele nao existir

# Engenharia de Recursos: Cálculo de Score de Risco por IP
cat("Calculando scores de risco por IP...\n")
# Cria um novo dataframe consolidando métricas por IP de origem
ip_risk <- df %>%
  group_by(src_ip) %>% # Agrupa os dados por endereço IP de origem
  summarise(
    total_conns = n(), # Conta o número total de conexões por IP
    unique_ports = n_distinct(dest_port), # Conta quantas portas diferentes foram visadas
    s0_conns = sum(conn_state == "S0", na.rm = TRUE), # Soma conexões sem resposta (S0)
    total_bytes_sent = sum(orig_bytes, na.rm = TRUE), # Soma o volume total de bytes enviados
    mitre_events = sum(mitre_attack_tactics != "none" & !is.na(mitre_attack_tactics), na.rm = TRUE), # Conta alertas MITRE
    .groups = 'drop' # Desfaz o agrupamento após o resumo
  ) %>%
  mutate(
    # Calcula um Score de Risco: S0 tem peso baixo, portas únicas peso médio e alertas MITRE peso alto
    risk_score = (s0_conns * 0.5) + (unique_ports * 10) + (mitre_events * 100)
  )


# Fingerprint de Exfiltração
cat("Gerando análise de exfiltração...\n")

# Filtra bytes válidos, soma por IP e porta, e pega os 15 maiores fluxos
exfil_data <- df %>%
  filter(!is.na(orig_bytes)) %>%
  group_by(src_ip, dest_port) %>%
  summarise(total_bytes = sum(orig_bytes), .groups = 'drop') %>%
  arrange(desc(total_bytes)) %>%
  slice_max(total_bytes, n = 15)

# Cria gráfico de barras horizontais para visualizar a exfiltração
ggplot(exfil_data, aes(x = reorder(src_ip, total_bytes), y = total_bytes, fill = as.factor(dest_port))) +
  geom_col() + # Desenha colunas
  coord_flip() + # Rotaciona o gráfico para facilitar a leitura dos IPs
  scale_y_continuous(labels = label_number(scale_cut = cut_short_scale())) + # Formata bytes (K, M, G)
  labs(title = "Fingerprint de Exfiltração de Dados",
       subtitle = "Top fluxos de saída por IP e Porta",
       x = "IP de Origem", y = "Total de Bytes Enviados", fill = "Porta Destino") +
  theme_minimal()
# Salva o gráfico resultante como arquivo PNG
ggsave("analise_graficos/exfiltration_fingerprint.png")

# Correlação Tática-Comportamento - baseada em dados de mitre attck - uma "enciclopédia" global e gratuita de comportamentos de cibercriminosos
cat("Gerando correlação de táticas MITRE...\n")

# Filtra eventos com táticas MITRE e foca apenas nos 20 IPs de maior risco calculados anteriormente
mitre_corr <- df %>%
  filter(mitre_attack_tactics != "none" & !is.na(mitre_attack_tactics)) %>%
  count(src_ip, mitre_attack_tactics) %>%
  filter(src_ip %in% (ip_risk %>% slice_max(risk_score, n = 20) %>% pull(src_ip)))

# Cria gráfico de barras empilhadas para mostrar a composição de táticas por IP
ggplot(mitre_corr, aes(x = src_ip, y = n, fill = mitre_attack_tactics)) +
  geom_col(position = "stack") + # Empilha as táticas no mesmo IP
  coord_flip() + # Rotaciona o gráfico
  labs(title = "Táticas MITRE em IPs de Alto Risco",
       x = "IP de Origem", y = "Quantidade de Eventos", fill = "Tática") +
  theme_minimal()
# Salva o gráfico resultante como arquivo PNG
ggsave("analise_graficos/mitre_correlation.png")

# Sequência Temporal de Invasão
cat("Gerando timeline de eventos significativos...\n")

# Extrai a lista dos 5 IPs com o maior score de risco
top_suspects <- ip_risk %>% slice_max(risk_score, n = 5) %>% pull(src_ip)

# Agrupa as conexões desses suspeitos por minuto para criar a série temporal
timeline_data <- df %>%
  filter(src_ip %in% top_suspects) %>%
  mutate(hora = floor_date(datetime, "1 minute")) %>%
  group_by(hora, src_ip) %>%
  summarise(conns = n(), .groups = 'drop')

# Cria gráfico de linhas para observar picos de atividade dos atacantes ao longo do tempo
ggplot(timeline_data, aes(x = hora, y = conns, color = src_ip)) +
  geom_line(size = 1) + # Desenha linhas com espessura 1
  labs(title = "Sequência Temporal de Atividade Suspeita",
       subtitle = "Comportamento dos Top 5 IPs mais arriscados",
       x = "Tempo", y = "Conexões por Minuto", color = "IP Atacante") +
  theme_minimal()
# Salva o gráfico resultante como arquivo PNG
ggsave("analise_graficos/attack_sequence.png")


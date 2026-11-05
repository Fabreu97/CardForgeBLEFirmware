# CardForge BLE Firmware

Firmware de vinculação e provisionamento via **Bluetooth Low Energy (BLE)** para Raspberry Pi 4B rodando no ecossistema CardForge.

O Raspberry Pi não requer conexão prévia com a internet para ser configurado. Através da comunicação BLE diretamente com o aplicativo CardForge, o dispositivo é capaz de:
1. Autenticar solicitações usando a senha individual da máquina.
2. Registrar usuários vinculados e autorizados para operar o equipamento.
3. Receber credenciais de Wi-Fi e conectar-se à rede sem fio via `NetworkManager` (`nmcli`).

---

## 🛠️ Tecnologias e Requisitos

- **Hardware:** Raspberry Pi 4B (ou compatível com BLE e Wi-Fi).
- **Sistema Operacional:** Raspberry Pi OS Bookworm (com `NetworkManager` ativo).
- **Linguagem:** Python 3.11+
- **Dependências Chave:**
  - `bless` (servidor GATT assíncrono baseado em BlueZ)
  - `python-dotenv` (carregamento de variáveis de ambiente)
- **Ferramentas do Sistema:** `bluez`, `bluetoothctl`, `nmcli`, `rfkill`.

---

## 📁 Estrutura do Projeto

```text
.
├── cardforge_ble.py   # Script principal (servidor GATT, comandos CLI, Wi-Fi e Auth)
├── requirements.txt   # Dependências do projeto Python (versões fixadas)
├── setup.sh           # Script de instalação e provisionamento automatizado no Linux
├── .env-example       # Modelo de variáveis de ambiente
└── CONTRATO_BLE.md    # Especificação do protocolo BLE (se disponível)
```

---

## ⚙️ Configuração das Variáveis de Ambiente (`.env`)

Copie o arquivo de exemplo para criar a sua configuração local:

```bash
cp .env-example .env
```

### Parâmetros Suportados

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `MACHINE_MODEL` | `CardForge-M1` | Modelo da máquina (1-16 caracteres alfanuméricos/`-`). |
| `MACHINE_SERIAL` | *Obrigatório* | Número de série (1-8 caracteres alfanuméricos, ex: `001`). |
| `MACHINE_PASSWORD` | - | Senha em texto puro (mínimo 6 caracteres). Se definida, será convertida para hash via `secure-env`. |
| `MACHINE_PASSWORD_HASH` | - | Hash PBKDF2-SHA256 da senha. Prioritário em relação à senha em texto puro. |
| `WIFI_INTERFACE` | `wlan0` | Interface de rede sem fio monitorada e gerenciada. |
| `WIFI_CONNECT_TIMEOUT` | `20` | Timeout de conexão do Wi-Fi em segundos (5-120s). |
| `AUTH_MAX_ATTEMPTS` | `5` | Máximo de tentativas de autenticação antes do bloqueio (1-20). |
| `AUTH_LOCKOUT_SECONDS` | `60` | Tempo inicial de bloqueio após falhas consecutivas (5-3600s). |
| `SESSION_TTL_SECONDS` | `300` | Duração máxima da sessão autenticada (30-3600s). |
| `MAX_ALLOWED_USERS` | `20` | Limite máximo de usuários permitidos e salvos no dispositivo. |
| `DATA_DIR` | `/var/lib/cardforge` | Diretório onde os dados da máquina (`state.json`) são salvos. |
| `LOG_LEVEL` | `INFO` | Nível de log (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `WIFI_COUNTRY` | `BR` | Código ISO do país para regulamentação de rádio do Wi-Fi. |

---

## 🚀 Instalação e Provisionamento Automatizado

O script `setup.sh` prepara todo o ambiente no Raspberry Pi, compila ou configura o Python, instala serviços do D-Bus e Polkit, endurece as permissões e registra o serviço no `systemd`.

Instale executando o comando abaixo como `root` ou `sudo`:

```bash
sudo ./setup.sh
```

### Opções Avançadas do `setup.sh`

O script aceita variáveis de ambiente no momento do disparo:

```bash
# Usar o Python 3.11 do sistema sem compilar a versão estática
sudo USE_SYSTEM_PYTHON=1 ./setup.sh

# Rodar o serviço sob o usuário root
sudo SERVICE_USER=root ./setup.sh

# Ignorar o 'apt full-upgrade' para acelerar a instalação
sudo SKIP_UPGRADE=1 ./setup.sh
```

---

## 💻 Uso da Linha de Comando (`cardforge_ble.py`)

Você pode interagir diretamente com o executável Python para tarefas de manutenção ou validação.

### 1. Iniciar o servidor BLE
```bash
python cardforge_ble.py run --env .env
```

### 2. Validar o arquivo de configuração
```bash
python cardforge_ble.py check --env .env
```

### 3. Gerar hash de senha manualmente
```bash
python cardforge_ble.py hash-password
```

### 4. Converter senha em texto puro para Hash no `.env`
Substitui automaticamente a entrada `MACHINE_PASSWORD` por `MACHINE_PASSWORD_HASH` no arquivo indicado. Se a senha for inválida ou o placeholder padrão, uma senha segura é gerada e exibida na tela.
```bash
python cardforge_ble.py secure-env .env
```

---

## 📡 Protocolo BLE (Visão Geral GATT)

- **Service UUID:** `a3c1f000-6d2e-4b8a-9c3f-2e7d5b1a9c40`
- **RX Characteristic (Write):** `a3c1f001-6d2e-4b8a-9c3f-2e7d5b1a9c40` (App -> Máquina)
- **TX Characteristic (Notify / Read):** `a3c1f002-6d2e-4b8a-9c3f-2e7d5b1a9c40` (Máquina -> App)

### Resumo dos Comandos Suportados (`cmd`)
1. `info`: Retorna o modelo, serial, versão de firmware e versão do protocolo.
2. `auth`: Autentica o usuário com nome de usuário e senha da máquina.
3. `wifi`: Envia parâmetros de SSID e senha para conexão de rede sem fio via `nmcli`.
4. `wifi_status`: Consulta o estado atual da conexão Wi-Fi (status, SSID e IP se conectado).
5. `logout`: Encerra a sessão ativa do usuário.

---

## 🛡️ Segurança

- **Armazenamento de Senha:** Utiliza hash derivado com **PBKDF2-SHA256** (mínimo de 300.000 iterações).
- **Proteção Brute-force:** A contagem de tentativas incorretas aciona o bloqueio temporário exponencial (`AUTH_LOCKOUT_SECONDS`).
- **Persistência Atômica:** O arquivo de estado local (`state.json`) utiliza gravação atômica com permissões restritas (`0600`) para prevenção de corrupção.
- **Isolamento no Systemd:** O serviço `cardforge-ble.service` utiliza regras restritivas como `ProtectHome`, `ProtectSystem=strict` e `NoNewPrivileges`.

---

## 📑 Gerenciamento do Serviço Systemd

Caso tenha executado o `setup.sh`, gerencie o daemon da aplicação com:

```bash
# Verificar status do serviço
sudo systemctl status cardforge-ble

# Visualizar logs em tempo real
journalctl -u cardforge-ble -f

# Reiniciar o serviço
sudo systemctl restart cardforge-ble
```
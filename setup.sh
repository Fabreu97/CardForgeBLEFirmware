#!/usr/bin/env bash
# =============================================================================
#  setup.sh - Prepara o Raspberry Pi 4B para o CardForge BLE
#
#  Uso (na pasta com cardforge_ble.py, requirements.txt e .env/.env-example):
#     sudo ./setup.sh
#
#  Variáveis opcionais:
#     PYTHON_VERSION=3.11.10   versão do Python compilada para o serviço
#     USE_SYSTEM_PYTHON=1      usa o python3 do sistema (>= 3.11) e não compila
#     SERVICE_USER=cardforge   usuário do serviço (use "root" só se necessário)
#     SKIP_UPGRADE=1           pula o apt full-upgrade
#
#  Instala em:
#     /opt/cardforge                 código + venv + Python (dono root, só leitura)
#     /etc/cardforge/cardforge.env   configuração (640, senha com hash)
#     /var/lib/cardforge/state.json  usuários permitidos + machine_id (600)
#     serviço systemd: cardforge-ble
# =============================================================================
set -euo pipefail

PYTHON_VERSION="${PYTHON_VERSION:-3.11.10}"
USE_SYSTEM_PYTHON="${USE_SYSTEM_PYTHON:-0}"
SERVICE_USER="${SERVICE_USER:-cardforge}"
SKIP_UPGRADE="${SKIP_UPGRADE:-0}"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/cardforge"
VENV_DIR="${INSTALL_DIR}/venv"
PY_PREFIX="${INSTALL_DIR}/python/${PYTHON_VERSION}"
CONF_DIR="/etc/cardforge"
ENV_FILE="${CONF_DIR}/cardforge.env"
SERVICE="cardforge-ble"
UNIT_FILE="/etc/systemd/system/${SERVICE}.service"

info() { echo -e "\e[1;34m[INFO]\e[0m  $*"; }
ok()   { echo -e "\e[1;32m[OK]\e[0m    $*"; }
warn() { echo -e "\e[1;33m[AVISO]\e[0m $*"; }
erro() { echo -e "\e[1;31m[ERRO]\e[0m  $*" >&2; exit 1; }

# ------------------------------ Verificações ---------------------------------
[[ $EUID -eq 0 ]] || erro "Execute com sudo:  sudo ./setup.sh"
for f in cardforge_ble.py requirements.txt; do
    [[ -f "${SRC_DIR}/${f}" ]] || erro "Arquivo ${f} não encontrado em ${SRC_DIR}"
done
if [[ -f "${SRC_DIR}/.env" ]]; then
    ENV_SRC="${SRC_DIR}/.env"
elif [[ -f "${SRC_DIR}/.env-example" ]]; then
    ENV_SRC="${SRC_DIR}/.env-example"
else
    erro "Crie o .env (copie de .env-example) em ${SRC_DIR}"
fi

# --------------------------- 1. Pacotes do sistema ---------------------------
info "Atualizando pacotes..."
apt-get update -y
[[ "$SKIP_UPGRADE" == "1" ]] || DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y

info "Instalando Bluetooth e utilitários..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    bluetooth bluez rfkill ca-certificates git
command -v nmcli >/dev/null 2>&1 || \
    erro "nmcli não encontrado. Use o Raspberry Pi OS Bookworm (NetworkManager)."
ok "Pacotes do sistema instalados."

# ------------------------------ 2. Python ------------------------------------
py_version() { "$1" -c 'import platform; print(platform.python_version())' 2>/dev/null || true; }

if [[ "$USE_SYSTEM_PYTHON" == "1" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv
    PY="/usr/bin/python3"
    "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 11))' || \
        erro "Python do sistema é $(py_version "$PY"); é preciso 3.11 ou superior."
    warn "Usando o Python do sistema ($(py_version "$PY")) em vez do ${PYTHON_VERSION}."
elif [[ "$(py_version "${PY_PREFIX}/bin/python3")" == "$PYTHON_VERSION" ]]; then
    PY="${PY_PREFIX}/bin/python3"
    ok "Python ${PYTHON_VERSION} já compilado em ${PY_PREFIX}."
else
    info "Instalando dependências de compilação do Python..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential curl libssl-dev zlib1g-dev libbz2-dev libreadline-dev \
        libsqlite3-dev libncursesw5-dev xz-utils tk-dev libxml2-dev \
        libxmlsec1-dev libffi-dev liblzma-dev uuid-dev
    info "Compilando Python ${PYTHON_VERSION} (leva de 10 a 25 minutos no Pi 4)..."
    BUILD_TMP="$(mktemp -d)"
    trap 'rm -rf "$BUILD_TMP"' EXIT
    # python-build (do pyenv) baixa o código e confere o checksum SHA-256
    git clone --depth 1 https://github.com/pyenv/pyenv.git "${BUILD_TMP}/pyenv"
    mkdir -p "${INSTALL_DIR}/python"
    "${BUILD_TMP}/pyenv/plugins/python-build/bin/python-build" "$PYTHON_VERSION" "$PY_PREFIX"
    PY="${PY_PREFIX}/bin/python3"
    [[ "$(py_version "$PY")" == "$PYTHON_VERSION" ]] || erro "Falha ao compilar o Python ${PYTHON_VERSION}."
    ok "Python ${PYTHON_VERSION} instalado em ${PY_PREFIX}."
fi

# --------------------------- 3. Usuário do serviço ---------------------------
if [[ "$SERVICE_USER" == "root" ]]; then
    SERVICE_GROUP="root"
    warn "Serviço vai rodar como root (SERVICE_USER=root)."
else
    SERVICE_GROUP="$SERVICE_USER"
    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        info "Criando usuário de sistema '${SERVICE_USER}'..."
        useradd --system --no-create-home --home-dir /nonexistent \
                --shell /usr/sbin/nologin "$SERVICE_USER"
    fi
    for g in bluetooth netdev; do
        getent group "$g" >/dev/null && usermod -aG "$g" "$SERVICE_USER"
    done

    # D-Bus: permite falar com o BlueZ (registrar serviço GATT e anúncio)
    cat > /etc/dbus-1/system.d/cardforge.conf <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="${SERVICE_USER}">
    <allow send_destination="org.bluez"/>
  </policy>
</busconfig>
EOF
    # Polkit: permite controlar o Wi-Fi pelo NetworkManager
    if [[ -d /etc/polkit-1/rules.d ]]; then
        cat > /etc/polkit-1/rules.d/50-cardforge.rules <<EOF
// CardForge: o serviço pode configurar o Wi-Fi pelo NetworkManager
polkit.addRule(function(action, subject) {
    if (subject.user == "${SERVICE_USER}" &&
        action.id.indexOf("org.freedesktop.NetworkManager.") == 0) {
        return polkit.Result.YES;
    }
});
EOF
    fi
    if [[ -d /etc/polkit-1/localauthority ]]; then
        mkdir -p /etc/polkit-1/localauthority/50-local.d
        cat > /etc/polkit-1/localauthority/50-local.d/50-cardforge.pkla <<EOF
[CardForge NetworkManager]
Identity=unix-user:${SERVICE_USER}
Action=org.freedesktop.NetworkManager.*
ResultAny=yes
ResultInactive=yes
ResultActive=yes
EOF
    fi
    systemctl reload dbus 2>/dev/null || true
    ok "Usuário '${SERVICE_USER}' configurado (bluetooth + NetworkManager)."
fi

# ------------------------- 4. Código e ambiente Python -----------------------
info "Instalando o código em ${INSTALL_DIR}..."
install -d -m 755 -o root -g root "$INSTALL_DIR"
install -m 644 -o root -g root "${SRC_DIR}/cardforge_ble.py" "${SRC_DIR}/requirements.txt" "$INSTALL_DIR/"
[[ -f "${SRC_DIR}/CONTRATO_BLE.md" ]] && install -m 644 "${SRC_DIR}/CONTRATO_BLE.md" "$INSTALL_DIR/"

info "Criando venv e instalando dependências..."
"$PY" -m venv --clear "$VENV_DIR"
"${VENV_DIR}/bin/pip" install --no-cache-dir --upgrade pip
"${VENV_DIR}/bin/pip" install --no-cache-dir -r "${INSTALL_DIR}/requirements.txt"
chown -R root:root "$INSTALL_DIR"
ok "Dependências instaladas."

# ---------------------------- 5. Configuração --------------------------------
install -d -m 750 -o root -g "$SERVICE_GROUP" "$CONF_DIR"
if [[ -f "$ENV_FILE" ]]; then
    info "Mantendo a configuração existente em ${ENV_FILE}."
else
    info "Instalando configuração a partir de $(basename "$ENV_SRC")..."
    install -m 640 -o root -g "$SERVICE_GROUP" "$ENV_SRC" "$ENV_FILE"
fi

SECURE_OUT="$("${VENV_DIR}/bin/python" "${INSTALL_DIR}/cardforge_ble.py" secure-env "$ENV_FILE")"
echo "$SECURE_OUT" | grep -v "SENHA GERADA" || true
GENERATED_PW="$(echo "$SECURE_OUT" | sed -n 's/^SENHA GERADA: //p')"
chown root:"$SERVICE_GROUP" "$ENV_FILE"
chmod 640 "$ENV_FILE"
if [[ "$ENV_SRC" == "${SRC_DIR}/.env" ]] && grep -qE '^\s*MACHINE_PASSWORD=' "$ENV_SRC"; then
    warn "${ENV_SRC} ainda tem a senha em texto puro. Apague-o: rm ${ENV_SRC}"
fi

CHECK_OUT="$("${VENV_DIR}/bin/python" "${INSTALL_DIR}/cardforge_ble.py" --env "$ENV_FILE" check)" || \
    erro "Configuração inválida. Corrija ${ENV_FILE} e rode o setup de novo."
ok "$CHECK_OUT"
BLE_NAME="$(echo "$CHECK_OUT" | sed -n 's/.*nome BLE: \([^ |]*\).*/\1/p')"

# --------------------------- 6. Bluetooth e Wi-Fi ----------------------------
info "Ativando Bluetooth..."
rfkill unblock bluetooth || true
systemctl enable --now bluetooth
sleep 2
bluetoothctl power on >/dev/null 2>&1 || true
bluetoothctl show | grep -q "Powered: yes" && ok "Bluetooth ligado." || \
    warn "Bluetooth não aparece ligado. Verifique: bluetoothctl show"

WIFI_COUNTRY="$(grep -E '^WIFI_COUNTRY=' "$ENV_FILE" | tail -1 | cut -d= -f2 | tr -d '"'"'"' ' || true)"
WIFI_COUNTRY="${WIFI_COUNTRY:-BR}"
info "Preparando o rádio Wi-Fi (país ${WIFI_COUNTRY}, sem rede configurada)..."
command -v raspi-config >/dev/null 2>&1 && \
    { raspi-config nonint do_wifi_country "$WIFI_COUNTRY" || warn "Falha ao definir o país do Wi-Fi."; }
rfkill unblock wifi || true
nmcli radio wifi on || true

# ------------------------------ 7. Serviço -----------------------------------
info "Instalando o serviço ${SERVICE}..."
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=CardForge BLE - vinculação da máquina (${BLE_NAME})
After=bluetooth.service NetworkManager.service
Requires=bluetooth.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
ExecStart=${VENV_DIR}/bin/python ${INSTALL_DIR}/cardforge_ble.py --env ${ENV_FILE} run
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
Restart=always
RestartSec=5

# Endurecimento
StateDirectory=cardforge
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
sleep 4
if systemctl is-active --quiet "$SERVICE"; then
    ok "Serviço ${SERVICE} rodando."
else
    journalctl -u "$SERVICE" -n 40 --no-pager
    warn "O serviço não iniciou. Veja o log acima."
    [[ "$SERVICE_USER" != "root" ]] && \
        warn "Se o erro for de permissão no BlueZ, rode: sudo SERVICE_USER=root SKIP_UPGRADE=1 ./setup.sh"
fi

# ------------------------------ Resumo ---------------------------------------
echo
echo "=============================================================="
echo "  CardForge BLE instalado"
echo "--------------------------------------------------------------"
echo "  Nome no Bluetooth : ${BLE_NAME}"
if [[ -n "$GENERATED_PW" ]]; then
echo "  SENHA DA MÁQUINA  : ${GENERATED_PW}   <- anote, não será mostrada de novo"
fi
echo "  Python            : $(py_version "${VENV_DIR}/bin/python")"
echo "  Configuração      : ${ENV_FILE}"
echo "  Usuários          : /var/lib/cardforge/state.json"
echo "  Logs              : journalctl -u ${SERVICE} -f"
echo "  Reiniciar         : sudo systemctl restart ${SERVICE}"
echo "=============================================================="

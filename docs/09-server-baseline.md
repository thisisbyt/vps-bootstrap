# Server baseline

## Исходные предположения

Хостер уже установил Ubuntu.

Пользователь имеет:

- IP сервера;
- root password или sudo user;
- SSH-доступ.

Нельзя предполагать наличие дополнительных пакетов.

## Поддерживаемая ОС

Primary target проекта — Ubuntu Server 24.04 LTS.

Конкретные версии должны задаваться в compatibility matrix.

Не делать вид, что неизвестная будущая Ubuntu автоматически поддерживается.

## Минимальные проверки ресурсов

До установки показать:

```text
CPU
RAM
Swap
Disk total
Disk free
Architecture
IPv4
IPv6
```

Если сервер слишком мал для выбранного набора сервисов, выдать warning до установки.

## Пакеты bootstrap

Минимально необходимый набор определяется реализацией, но проект должен уметь поставить недостающие зависимости самостоятельно.

Ожидаемые часто используемые инструменты:

```bash
sudo apt-get update
sudo apt-get install -y \
  ca-certificates \
  curl \
  git \
  python3 \
  python3-venv \
  jq \
  unzip \
  openssl \
  dnsutils
```

Не считать этот список неизменным. Любой добавленный пакет должен иметь назначение.

## Проверки после установки инструментов

```bash
curl --version
git --version
python3 --version
jq --version
openssl version
dig -v
```

## Сетевые диагностические инструменты

Использовать стандартные:

```bash
ip addr
ip route
ss -lntup
dig
curl
```

`netstat` не должен быть обязательным, если ту же задачу решает `ss`.

## Логи

Рабочие логи installer:

```text
/var/log/vps-bootstrap/
```

Логи должны быть полезными для последующего разбора в ChatGPT/Codex и не содержать секретов.

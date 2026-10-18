#!/usr/bin/env bash
# Устанавливает sing: симлинки из репозитория в ~/.local/bin, ~/.local/share/sing
# и ~/.proxychains. Существующие обычные файлы сохраняются с суффиксом .bak.
# Секреты (sing.sub, custom.txt, sing.json) не трогает.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$HOME/.config/sing-box"

# Создаёт симлинк target -> source; обычный файл на месте target переименовывает в .bak.
link_file() {
  local source_path="$1" target_path="$2"
  mkdir -p "$(dirname "$target_path")"
  if [[ -e "$target_path" && ! -L "$target_path" ]]; then
    mv "$target_path" "$target_path.bak"
    echo "backup: $target_path.bak"
  fi
  ln -sfn "$source_path" "$target_path"
  echo "link:   $target_path -> $source_path"
}

# Проверяет зависимости и печатает подсказку по установке недостающих.
check_dependencies() {
  local missing_commands=()
  for command_name in sing-box proxychains4 python3 nc; do
    command -v "$command_name" >/dev/null 2>&1 || missing_commands+=("$command_name")
  done
  if ((${#missing_commands[@]})); then
    echo "warning: не найдено: ${missing_commands[*]} (brew install sing-box proxychains-ng)" >&2
  fi
}

link_file "$REPO_DIR/bin/sing" "$HOME/.local/bin/sing"
link_file "$REPO_DIR/share/select.py" "$HOME/.local/share/sing/select.py"
link_file "$REPO_DIR/proxychains/sing.conf" "$HOME/.proxychains/sing.conf"

# Переносит файлы старой версии (blanc.*) в sing.*, если новых ещё нет.
migrate_from_blanc() {
  local suffix
  for suffix in sub json current pid; do
    if [[ -f "$CONFIG_DIR/blanc.$suffix" && ! -e "$CONFIG_DIR/sing.$suffix" ]]; then
      mv "$CONFIG_DIR/blanc.$suffix" "$CONFIG_DIR/sing.$suffix"
      echo "moved:  blanc.$suffix -> sing.$suffix"
    fi
  done
}

mkdir -p "$CONFIG_DIR"
migrate_from_blanc
if [[ ! -f "$CONFIG_DIR/sing.sub" ]]; then
  echo "next:   положи URL подписки в $CONFIG_DIR/sing.sub (chmod 600), затем: sing select"
fi

check_dependencies

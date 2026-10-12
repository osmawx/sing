#!/usr/bin/env bash
# Устанавливает blanc: симлинки из репозитория в ~/.local/bin, ~/.local/share/blanc
# и ~/.proxychains. Существующие обычные файлы сохраняются с суффиксом .bak.
# Секреты (blanc.sub, custom.txt, blanc.json) не трогает.
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

link_file "$REPO_DIR/bin/blanc" "$HOME/.local/bin/blanc"
link_file "$REPO_DIR/share/select.py" "$HOME/.local/share/blanc/select.py"
link_file "$REPO_DIR/proxychains/blanc.conf" "$HOME/.proxychains/blanc.conf"

mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/blanc.sub" ]]; then
  echo "next:   положи URL подписки в $CONFIG_DIR/blanc.sub (chmod 600), затем: blanc select"
fi

check_dependencies

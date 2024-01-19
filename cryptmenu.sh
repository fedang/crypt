#!/bin/sh
#
# Script with a dmenu integration for crypt

set -o pipefail

typeit=0
if [[ $1 == "--type" ]]; then
	typeit=1
	shift
fi

list=$(crypt list --plain | awk '{print $1"["$2"]"}')
[[ -n "$list" ]] || exit 1
name=$(echo "$list" | dmenu "$@" | sed 's/\(\.*\)\[.*\]/\1/')
[[ -n "$name" ]] || exit

if [[ $typeit -eq 0 ]]; then
	# FIXME: clear the clipboard
	crypt show $name | xclip -selection clipboard
else
	crypt show $name | { IFS= read -r line; printf %s "$line"; } | xdotool type --clearmodifiers --file -
fi

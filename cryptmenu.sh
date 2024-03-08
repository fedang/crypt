#!/bin/sh
#
#    Copyright (C) 2023 Federico Angelilli <mail@fedang.net>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#    The work that is used or that has inspired this project is credited
#    in the CREDITS file.

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

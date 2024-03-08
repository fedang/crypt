#!/bin/bash
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

single_prompt() {
	local inp
	read -r -p "Enter contents of $NAME ($ENTRY): " -e inp
	echo "$inp" > "$FILE"
}

long_prompt() {
	printf "Enter contents of $NAME ($ENTRY) and press Ctrl+D when finished:\n\n"
	cat - > "$FILE"
}

double_prompt() {
	local inp inp2
	read -r -p "Enter contents of $NAME ($ENTRY): " -s inp || error "Failed prompt"
	echo
	read -r -p "Retype contents of $NAME: " -s inp2 || error "Failed prompt"
	echo

	[[ "$inp" == "$inp2" ]] || error "Contents don't match..."
	echo "$inp" > "$FILE"
}

prompt() {
	local opts long=0 double=0
	opts="$($GETOPT -o ld -l long,double -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-l|--long) long=1; shift ;;
		-d|--double) double=1; shift ;;
		--) shift; break ;;
	esac done

	[[ $err -ne 0 || ( $long -eq 1 && $double -eq 1 ) || $# -ne 0 ]] && error "Invalid options for prompt ($ACTION action for $NAME)"

	[[ $long -eq 1 ]] && long_prompt && return
	[[ $double -eq 1 ]] && double_prompt && return
	single_prompt
}

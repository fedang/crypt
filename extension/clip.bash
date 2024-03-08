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

X_SELECTION="${CRYPT_X_SELECTION:-clipboard}"
CLIP_TIME="${CRYPT_STORE_CLIP_TIME:-45}"
BASE64="base64"

# This function was adapted from pass
_clip() {
	if [[ -n $WAYLAND_DISPLAY ]]; then
		local copy_cmd=( wl-copy )
		local paste_cmd=( wl-paste -n )
		if [[ $X_SELECTION == primary ]]; then
			copy_cmd+=( --primary )
			paste_cmd+=( --primary )
		fi
		local display_name="$WAYLAND_DISPLAY"
	elif [[ -n $DISPLAY ]]; then
		local copy_cmd=( xclip -selection "$X_SELECTION" )
		local paste_cmd=( xclip -o -selection "$X_SELECTION" )
		local display_name="$DISPLAY"
	else
		error "No X11 or Wayland display detected"
	fi

	if [[ "$2" == "clear" ]]; then
		local sleep_argv0="password store sleep on display $display_name"

		# NOTE: base64 is needed to store binary data in bash
		pkill -f "^$sleep_argv0" 2>/dev/null && sleep 0.5
		local before="$("${paste_cmd[@]}" 2>/dev/null | $BASE64)"
		echo -n "$1" | "${copy_cmd[@]}" || error "Could not copy data to the clipboard"
		(
			( exec -a "$sleep_argv0" bash <<< "trap 'kill %1' TERM; sleep '$CLIP_TIME' & wait" )
			local now="$("${paste_cmd[@]}" | $BASE64)"
			[[ $now != $(echo -n "$1" | $BASE64) ]] && before="$now"
			qdbus org.kde.klipper /klipper org.kde.klipper.klipper.clearClipboardHistory &>/dev/null
			echo "$before" | $BASE64 -d | "${copy_cmd[@]}"
		) >/dev/null 2>&1 & disown
		echo "Copied $NAME to clipboard. Will clear in $CLIP_TIME seconds."
	else
		echo -n "$1" | "${copy_cmd[@]}" || error "Could not copy data to the clipboard"
		echo "Copied $NAME to clipboard"
	fi
}

clip_file() {
	local opts noclear=clear
	opts="$($GETOPT -o '' -l clip-persistent -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		--clip-persistent) noclear=; shift ;;
		--) shift; break ;;
	esac done
	_clip "$(<"$FILE")" "$noclear"
}

clip_wrap() {
	local cmd="$1" args=() clip=0 noclear=clear
	shift

	# NOTE: For whatever reason here I didn't use getopt
	for a in "$@"; do
		case $a in
			-c|--clip) clip=1 ;;
			--clip-persistent) clip=1; noclear= ;;
			*) args+="$a" ;;
		esac
	done

	if [[ $clip -eq 1 ]]; then
		_clip "$(eval "$cmd" "${args[@]}")" "$noclear"
	else
		eval "$cmd" "${args[@]}"
	fi
}

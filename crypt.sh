#!/usr/bin/env bash
#
#    Copyright (C) 2023  Federico Angelilli <mail@fedang.net>
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

umask 077
set -o pipefail

# TODO: Is this really needed
shopt -s nullglob

CRYPT_PATH="${CRYPT_PATH:-~/.crypt}"
CRYPT_ARCHIVE="${CRYPT_ARCHIVE:-.crypt.tar.gpg}"

# UTILITIES
declare -A _colors=(
	["bold"]="$(tput bold)" 		["reset"]="$(tput sgr0)"
	["black"]="$(tput setaf 0)" 	["gray"]="$(tput setaf 8)"
	["red"]="$(tput setaf 1)"		["bright-red"]="$(tput setaf 9)"
	["green"]="$(tput setaf 2)"		["bright-green"]="$(tput setaf 10)"
	["yellow"]="$(tput setaf 3)"	["bright-yellow"]="$(tput setaf 11)"
	["blue"]="$(tput setaf 4)"		["bright-blue"]="$(tput setaf 12)"
	["magenta"]="$(tput setaf 5)"	["bright-magenta"]="$(tput setaf 13)"
	["cyan"]="$(tput setaf 6)"		["bright-cyan"]="$(tput setaf 14)"
	["white"]="$(tput setaf 7)"		["bright-white"]="$(tput setaf 15)"
)

_color() {
	IFS=',' read -ra arr <<< "$@"
	for c in "${arr[@]}"; do
		printf "%s" "${_colors[$c]}"
	done
}

error() {
	echo "$(_color red,bold)${2:-Error}$(_color reset): $1" >&2
	exit 1
}

confirm() {
	[[ -t 0 ]] || return 0
	local ans
	read -r -p "$1 [y/N] " ans
	[[ $ans == [yY] ]] || exit 1
}

check_paths() {
	local path
	for path in "$@"; do
		[[ $path =~ /\.\.$ || $path =~ ^\.\./ || $path =~ /\.\./ || $path =~ ^\.\.$ ]] \
		&& error "You have passed a sneaky path..."
	done
}

make_tmpdir() {
	[[ -n $SECURE_TMPDIR ]] && return
	local template="$PROGRAM.XXXXXXXXXXXXX"
	if [[ -d /dev/shm && -w /dev/shm && -x /dev/shm ]]; then
		SECURE_TMPDIR="$(mktemp -d "/dev/shm/$template")"
		remove_tmpfile() {
			rm -rf "$SECURE_TMPDIR"
		}
		trap remove_tmpfile EXIT
	else
		[[ $1 == "nowarn" ]] || confirm "$(cat <<-_EOF
		Your system does not have /dev/shm, which means that it may
		be difficult to entirely erase the temporary non-encrypted
		password file after editing.

		Are you sure you would like to continue?
		_EOF
		)"
		SECURE_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/$template")"
		shred_tmpfile() {
			find "$SECURE_TMPDIR" -type f -exec $SHRED {} +
			rm -rf "$SECURE_TMPDIR"
		}
		trap shred_tmpfile EXIT
	fi
}

# GIT HANDLING
unset GIT_DIR GIT_WORK_TREE GIT_NAMESPACE GIT_INDEX_FILE GIT_INDEX_VERSION GIT_OBJECT_DIRECTORY GIT_COMMON_DIR
export GIT_CEILING_DIRECTORIES="$CRYPT_PATH/.."

git_prep() {
	[[ $CLOSED -eq 1 ]] && error "To update git you must open the crypt."

	INNER_GIT_DIR="${1%/*}"
	while [[ ! -d $INNER_GIT_DIR && ${INNER_GIT_DIR%/*}/ == "${CRYPT_PATH%/}/"* ]]; do
		INNER_GIT_DIR="${INNER_GIT_DIR%/*}"
	done
	[[ $(git -C "$INNER_GIT_DIR" rev-parse --is-inside-work-tree 2>/dev/null) == true ]] || INNER_GIT_DIR=""
}

git_track() {
	[[ -n $INNER_GIT_DIR ]] || error "git repository is missing. Try to reinitialize the crypt."
	git -C "$INNER_GIT_DIR" add "$1" || return
	[[ -n $(git -C "$INNER_GIT_DIR" status --porcelain "$1") ]] || return
	git_commit "$2" "$3"
}

git_commit() {
	[[ -n $INNER_GIT_DIR ]] || error "git repository is missing. Try to reinitialize the crypt."
	git -C "$INNER_GIT_DIR" commit -m "$1" -m "$2"
}

git_init() {
	INNER_GIT_DIR="$CRYPT_PATH"
	git -C "$INNER_GIT_DIR" init || exit 1
	git_track "$CRYPT_PATH" "Add current contents."

	echo '*.gpg diff=gpg' > "$CRYPT_PATH/.gitattributes"
	git_track '.gitattributes' "Configure git for gpg file diff."

	echo "$CRYPT_ARCHIVE.*" > "$CRYPT_PATH/.gitignore"
	git_track '.gitignore' "Configure gitignore."

	git -C "$INNER_GIT_DIR" config --local diff.gpg.binary true
	git -C "$INNER_GIT_DIR" config --local diff.gpg.textconv "$GPG -d ${GPG_OPTS[*]}"
}

# ENCRYPTION
GPG_OPTS=( $CRYPT_GPG_OPTS "--quiet" "--yes" "--compress-algo=none" "--no-encrypt-to" )
GPG="gpg"
export GPG_TTY="${GPG_TTY:-$(tty 2>/dev/null)}"
command -v gpg2 &>/dev/null && GPG="gpg2"
[[ -n $GPG_AGENT_INFO || $GPG == "gpg2" ]] && GPG_OPTS+=( "--batch" "--use-agent" )

gpg_verify() {
	[[ -n $CRYPT_SIGNING_KEY ]] || return 0
	[[ -f $1.sig ]] || error "Signature for ${1#$CRYPT_PATH/} does not exist."
	local fingerprints="$($GPG $CRYPT_GPG_OPTS --verify --status-fd=1 "$1.sig" "$1" 2>/dev/null | sed -n 's/^\[GNUPG:\] VALIDSIG \([A-F0-9]\{40\}\) .* \([A-F0-9]\{40\}\)$/\1\n\2/p')"
	local fingerprint found=0
	for fingerprint in $CRYPT_SIGNING_KEY; do
		[[ $fingerprint =~ ^[A-F0-9]{40}$ ]] || continue
		[[ $fingerprints == *$fingerprint* ]] && { found=1; break; }
	done
	[[ $found -eq 1 ]] || error "Signature for ${1#$CRYPT_PATH/} is invalid."
}

gpg_sign() {
	[[ -n $CRYPT_SIGNING_KEY ]] || return 1
	local signing_keys=( ) key
	for key in $CRYPT_SIGNING_KEY; do
		signing_keys+=( --default-key $key )
	done

	$GPG "${GPG_OPTS[@]}" "${signing_keys[@]}" --detach-sign "$1" || error "Could not sign ${1#$CRYPT_PATH/}."
	key="$($GPG "${GPG_OPTS[@]}" --verify --status-fd=1 "$1.sig" "$1" 2>/dev/null | sed -n 's/^\[GNUPG:\] VALIDSIG [A-F0-9]\{40\} .* \([A-F0-9]\{40\}\)$/\1/p')"
	[[ -n $key ]] || error "Signing of ${1#$CRYPT_PATH/} unsuccessful."
}

gpg_recipients() {
	GPG_RECIPIENT_ARGS=( )
	GPG_RECIPIENTS=( )

	if [[ -n $CRYPT_GPG_KEY ]]; then
		for gpg_id in $CRYPT_GPG_KEY; do
			GPG_RECIPIENT_ARGS+=( "-r" "$gpg_id" )
			GPG_RECIPIENTS+=( "$gpg_id" )
		done
		return
	fi

	local current="$CRYPT_PATH/$1"
	while [[ $current != "$CRYPT_PATH" && ! -f $current/.gpg-id ]]; do
		current="${current%/*}"
	done
	current="$current/.gpg-id"

	[[ ! -f $current ]] && error "gpg-id is missing. You should initialize the crypt."
	gpg_verify "$current"

	local gpg_id
	while read -r gpg_id; do
		gpg_id="${gpg_id%%#*}" # strip comment
		[[ -n $gpg_id ]] || continue

		GPG_RECIPIENT_ARGS+=( "-r" "$gpg_id" )
		GPG_RECIPIENTS+=( "$gpg_id" )
	done < "$current"
}

reencrypt_path() {
	local prev_gpg_recipients="" gpg_keys="" current_keys="" index file
	local groups="$($GPG $CRYPT_GPG_OPTS --list-config --with-colons | grep "^cfg:group:.*")"
	while read -r -d "" file; do
		[[ -L $file ]] && continue
		local file_dir="${file%/*}"
		file_dir="${file_dir#$CRYPT_PATH}"
		file_dir="${file_dir#/}"
		local file_display="${file#$CRYPT_PATH/}"
		file_display="${file_display%.gpg}"
		local file_temp="${file}.tmp.${RANDOM}.${RANDOM}.${RANDOM}.${RANDOM}.--"

		gpg_recipients "$file_dir"
		if [[ $prev_gpg_recipients != "${GPG_RECIPIENTS[*]}" ]]; then
			for index in "${!GPG_RECIPIENTS[@]}"; do
				local group="$(sed -n "s/^cfg:group:$(sed 's/[\/&]/\\&/g' <<<"${GPG_RECIPIENTS[$index]}"):\\(.*\\)\$/\\1/p" <<<"$groups" | head -n 1)"
				[[ -z $group ]] && continue
				IFS=";" eval 'GPG_RECIPIENTS+=( $group )' # http://unix.stackexchange.com/a/92190
				unset "GPG_RECIPIENTS[$index]"
			done
			gpg_keys="$($GPG $CRYPT_GPG_OPTS --list-keys --with-colons "${GPG_RECIPIENTS[@]}" | sed -n 's/^sub:[^idr:]*:[^:]*:[^:]*:\([^:]*\):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[a-zA-Z]*e[a-zA-Z]*:.*/\1/p' | LC_ALL=C sort -u)"
		fi
		current_keys="$(LC_ALL=C $GPG $CRYPT_GPG_OPTS -v --no-secmem-warning --no-permission-warning --decrypt --list-only --keyid-format long "$file" 2>&1 | sed -nE 's/^gpg: public key is ([A-F0-9]+)$/\1/p' | LC_ALL=C sort -u)"

		if [[ $gpg_keys != "$current_keys" ]]; then
			echo "$file_display: reencrypting to ${gpg_keys//$'\n'/ }"
			$GPG -d "${GPG_OPTS[@]}" "$file" | $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file_temp" "${GPG_OPTS[@]}" &&
			mv "$file_temp" "$file" || rm -f "$file_temp"
		fi
		prev_gpg_recipients="${GPG_RECIPIENTS[*]}"
	done < <(find "$1" -path '*/.git' -prune -o -path '*/.extensions' -prune -o -iname '*.gpg' -print0)
}

# FILE INFO

# Entries
entries_ext=()
entries_name=()
entries_insert=()
entries_show=()
entries_edit=()
entries_color=()
entries_desc=()

# Unknown entry @unknown
entries_ext+=( "" )
entries_name+=( "unknown" )
entries_insert+=( "none" )
entries_show+=( "none" )
entries_edit+=( "none" )
entries_color+=( "gray" )
entries_desc+=( "Unrecognized files" )

# Unencrypted entry
entries_ext+=( "" )
entries_name+=( "unencrypted!" )
entries_insert+=( "none" )
entries_show+=( "none" )
entries_edit+=( "none" )
entries_color+=( "white,bold" )
entries_desc+=( "Unencrypted files (invalid!)" )

# Directory entry
entries_ext+=( "" )
entries_name+=( "" )
entries_insert+=( "none" )
entries_show+=( "none" )
entries_edit+=( "none" )
entries_color+=( "blue,bold" )
entries_desc+=( "Directories" )

# Basic actions
none() { echo "$(_color red,bold)No action specified$(_color reset)"; }
edit() { $EDITOR $FILE; }

load_extensions() {
	[[ -d "$CRYPT_PATH/.extensions" && $CLOSED -eq 0 ]] || return
	[[ -n "$CRYPT_LOAD_EXTENSIONS" ]] || return

	for f in $CRYPT_PATH/.extensions/*.bash; do
		[[ -n "$CRYPT_SIGNING_KEY" ]] && gpg_verify "$f"
		source "$f" "$f"
	done
}

load_entries() {
	[[ -d "$CRYPT_PATH" && $CLOSED -eq 0 ]] || return

	warn_entries() {
		printf "\n%s\n%s\n" \
			"If you have changed the .entries file yourself, you also need to update its signature." \
			"$(_color bold)Otherwise, you must check the .entries file as it is probably corrupted.$(_color reset)" >&2
	}
	trap warn_entries EXIT
	gpg_verify "$1"
	trap - EXIT

	while IFS= read -r line; do
		readarray -t arr < <(awk -v FPAT='(\"([^\"]|\\\\")*\"|[^[:space:]\"])+'  '{for (i=1; i<=NF; i++) print $i}' <<< $line)
		declare -A opts=( ["name"]="none" ["edit_action"]="none" ["insert_action"]="none" ["show_action"]="none" ["color"]="none" ["entry"]="none" )

		for w in "${arr[@]}"; do
			IFS='=' read -r k v <<< "$w"
			opts["$k"]="${v:-none}"
			case "${opts[$k]}" in
				$'"'*|$'\''*) opts["$k"]="${opts[$k]:1:-1}" ;;
				# TODO: Fix string parsing
			esac
		done

		[ -z "${opts[name]}" ] && error "Extension not given for entry #$i"
		[ -z "${opts[extension]}" ] && error "Extension not given for ${opts[name]}"

		local i
		case "${opts[extension]}" in
			\@unknown) i=0 ;;
			\@unencrypted) i=1 ;;
			\@directory) i=2 ;;
			*) i="${#entries_name[@]}" ;;
		esac

		entries_ext[$i]="${opts[extension]}"
		entries_name[$i]="${opts[name]}"
		entries_insert[$i]="${opts[insert_action]}"
		entries_show[$i]="${opts[show_action]}"
		entries_edit[$i]="${opts[edit_action]}"
		entries_color[$i]="${opts[color]}"
		entries_desc[$i]="${opts[description]}"

	done < <(sed "$1" \
		-e ':a;N;$!ba' \
		-e 's/[[:space:]]*#[^\n]*//g' \
		-e 's/\\\([[:space:]]*#[^\n]*\)\{0,1\}\n/ /g' \
		-e 's/\n*\n/\n/g' \
		-e 's/\(\(\"\([^\"]\|\\\"\)*\"\|[^[:space:]\"]\)\+\)[[:space:]]*=[[:space:]]*\(\(\"\([^\"]\|\\\"\)*\"\|[^[:space:]\"]\)\+\)/\1=\4/g' \
		-e 's/[[:space:]]*$//g')
}

find_entry() {
	local path="${1#$CRYPT_PATH/}" entry=0
	if [ -d "$CRYPT_PATH/$path" ]; then
		entry=2
	elif [[ -f "$CRYPT_PATH/$path" && "$path" != *.gpg ]]; then
		entry=1
	else
		for ((i = 3; i < ${#entries_ext[@]}; i++)); do
			if [[ "${path%.gpg}" == *.${entries_ext[$i]} ]]; then
				entry=$i
				break
			fi
		done
	fi
	echo "$entry"
}

check_file() {
	local path="${1#$CRYPT_PATH/}"
	path=${path%.gpg}
	[[ -f "$CRYPT_PATH/$path.gpg" ]] && echo "$path" && return

	local matches=()
	for ((i = 3; i < ${#entries_name[@]}; i++)); do
		[[ "$path" == *.${entries_ext[$i]}  ]] && echo "$path" && return
		if [[ -f "$CRYPT_PATH/$path.${entries_ext[$i]}.gpg" ]]; then
			matches+=( "$path.${entries_ext[$i]}" )
		fi
	done

	case ${#matches[@]} in
		0) [[ "$2" == "noask" ]] || confirm_file "$path" ;;
		1) echo "${matches[0]%.gpg}" ;;
		*) error "Ambiguous entry name: $(echo "${matches[@]}" | sed "s~$CRYPT_PATH/\([^[:space:]]*\).gpg~\1~g")" ;;
	esac
}

confirm_file() {
	local entry=$(find_entry "$1") ans=""
	[[ ($entry -eq 0 && ${#entries_ext[@]} -eq 4) || $entry -eq 1 || $entry -gt 3 ]] && echo "$1" && return

	while true; do
		for ((i = 3; i < ${#entries_name[@]}; i++)); do
			printf "%s) $(_color ${entries_color[$i]})%s$(_color reset)\t\t# %s\n" \
				"${entries_ext[$i]}" "${entries_name[$i]}" "${entries_desc[$i]:-No description}" >&2
		done
		read -r -p "Select one of the valid entries: " ans
		for ((i = 3; i < ${#entries_name[@]}; i++)); do
			if [[ "$ans" == "${entries_ext[$i]}" || "$ans" == "${entries_name[$i]}" ]]; then
				echo "${1%.}.$ans"
				return
			fi
		done
	done
}

# COMMANDS
GETOPT="getopt"
SHRED="shred -f -z"

cmd_info() {
	[[ $CLOSED -eq 1 ]] && error "You should open the crypt first."

	echo "Crypt info ($PRETTY_PATH)"

	for ((i = 0; i < ${#entries_name[@]}; i++)); do
		echo "entry #$i"
		echo "name: '${entries_name[$i]}'"
		echo "description: '${entries_desc[$i]}'"
		echo "extension: '${entries_ext[$i]}'"
		echo "edit_action: '${entries_edit[$i]}'"
		echo "show_action: '${entries_show[$i]}'"
		echo "insert_action: '${entries_insert[$i]}'"

		local reset="" color=""
		color=$(_color ${entries_color[$i]})
		[ -z "$color" ] || reset=$(_color reset)
		printf "color: '%s%s%s'\n\n" $color "${entries_color[$i]}" $reset
	done

	printf "${#entries_name[@]} entries in $PRETTY_PATH/.entries\n\n"

	[[ ! -d "$CRYPT_PATH/.extensions" ]] && echo "Extension directory not found ($PRETTY_PATH/.extensions)" && return

	printf "Extensions (%s)\n\n" "$([[ -n "$CRYPT_LOAD_EXTENSIONS" ]] && echo "loaded" || echo "not loaded")"

	local n=0
	for f in $CRYPT_PATH/.extensions/*.bash; do
		n=$(( n + 1 ))
		printf "%s [%s]\n" "${f#$CRYPT_PATH/.extensions/}" "$([[ -f "$f.sig" ]] && echo "With signature" || echo "No signature")"
	done

	printf "\n%s extensions in $PRETTY_PATH/.extensions\n" $n
}

cmd_init() {
	[[ $# -lt 1 ]] && error "$PROGRAM $COMMAND gpg-id..." Usage
	[[ $CLOSED -eq 1 ]] && error "You should open the crypt first."

	mkdir -v -p "$CRYPT_PATH/"
	git_init

	local gpg_id="$CRYPT_PATH/.gpg-id"
	git_prep "$gpg_id"

	if [[ $# -eq 1 && -z $1 ]]; then
		[[ ! -f "$gpg_id" ]] && error "$gpg_id does not exist and therefore it cannot be removed."

		rm -v -f "$gpg_id" || exit 1
		git -C "$INNER_GIT_DIR" rm -qr "$gpg_id"
		git_commit "Deinitialize $gpg_id."
		rmdir -p "${gpg_id%/*}" 2>/dev/null
	else
		printf "%s\n" "$@" > "$gpg_id"
		local id_print="$(printf "%s, " "$@")"
		echo "Crypt initialized for ${id_print%, }"

		git_track "$gpg_id" "Set GPG id to ${id_print%, }."
		gpg_sign "$gpg_id" && git_track "$gpg_id.sig" "Signing new GPG id with $CRYPT_SIGNING_KEY."

		local entries="$CRYPT_PATH/.entries"
		[[ ! -f "$entries" ]] && \
		echo 'extension=txt name=text edit_action="edit" insert_action="edit" show_action="cat $FILE" color=cyan description="Text file"' > "$entries" && \
		echo '# You can add whatever entry type you want, also using commands provided by extensions' >> "$entries" && \
		echo '# Remember to git commit and also sign (if you are using signatures) this file!' >> "$entries"

		git_track "$entries" "Add entries template."
		gpg_sign "$entries" && git_track "$entries.sig" "Signing entries template with $CRYPT_SIGNING_KEY."
	fi

	reencrypt_path "$CRYPT_PATH/"
	git_track "$CRYPT_PATH/" "Reencrypt crypt using new GPG id ${id_print%, }."
}

_cmd_action_file() {
	[[ $CLOSED -eq 1 ]] && error "The crypt must be open to $2 a file."

	local path="$1" file="$CRYPT_PATH/${path%.gpg}.gpg"
	git_prep "$file"

	[[ -d $file ]] && error "The given path is a directory."
	[[ "$2" == insert && -e $file ]] && confirm "File $path already exists. Overwrite it?"

	mkdir -p -v "$CRYPT_PATH/$(dirname -- "$path")"
	gpg_recipients "$(dirname -- "$path")"

	make_tmpdir
	local tmp_file="$(mktemp -u "$SECURE_TMPDIR/XXXXXX")-${path//\//-}.txt"

	local what="Insert"
	if [[ -f $file && "$2" != insert ]]; then
		$GPG -d -o "$tmp_file" "${GPG_OPTS[@]}" "$file" || exit 1
		what="Update"
	fi

	local cmd=none entry=$(find_entry "$file")
	case "$2" in
		insert) cmd="${entries_insert[$entry]}" ;;
		edit) cmd="${entries_edit[$entry]}" ;;
		show) cmd="${entries_show[$entry]}" ;;
		*) error "Unknown action" ;;
	esac
	cmd+=" ${@:3}"

	# Set environment
	FILE="$tmp_file"
	NAME="$path"
	ENTRY="${entries_name[$entry]}"
	ACTION="$2"
	MESSAGE="$what $ENTRY entry \`$path\`."
	set --

	eval "$cmd"
	[[ -f $tmp_file ]] || error "File not saved."

	$GPG -d -o - "${GPG_OPTS[@]}" "$file" 2>/dev/null | diff - "$tmp_file" &>/dev/null && \
	([[ "$2" != edit ]] || echo "File unchanged.") && return

	while ! $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file" "${GPG_OPTS[@]}" "$tmp_file"; do
		confirm "GPG encryption failed. Would you like to try again?"
	done

	git_track "$file" "$MESSAGE" "After $ACTION action for $NAME ($ENTRY)."
	unset -v FILE NAME ENTRY ACTION MESSAGE
}


cmd_insert() {
	[[ $# -lt 1 ]] && error "$PROGRAM $COMMAND file" Usage

	local path="${1%/}"
	shift
	check_paths "$path"
	path=$(confirm_file "$path")
	_cmd_action_file "$path" insert "$@"
}

cmd_edit() {
	[[ $# -lt 1 ]] && error "$PROGRAM $COMMAND file" Usage

	local path="${1%/}"
	shift
	check_paths "$path"
	path=$(check_file "$path")
	[[ $? -eq 0 ]] || exit 1
	[[ -z "$path" ]] && error "$1 not found in the crypt"
	_cmd_action_file "$path" edit "$@"

}

cmd_show() {
	local path="${1%/}"
	check_paths "$path"

	if [[ -d $CRYPT_PATH/$path ]]; then
		[[ -z $path ]] && path="$CRYPT_PATH"
		cmd_list "$path"
	elif [[ -z "$path" ]]; then
		error "Try to initialize the crypt."
	else
		[[ $CLOSED -eq 1 ]] && error "The crypt must be open to show a file."

		shift
		path=$(check_file "$path" noask)
		[[ $? -eq 0 ]] || exit 1

		if [[ -z "$path" ]]; then
			error "$1 not found in the crypt"
		elif [[ -f "$CRYPT_PATH/$path.gpg" ]]; then
			_cmd_action_file "$path" show "$@"
		else
			error "Try to initialize the crypt."
		fi
	fi
}

cmd_remove() {
	local opts recursive="" force=0
	opts="$($GETOPT -o rf -l recursive,force -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-r|--recursive) recursive="-r"; shift ;;
		-f|--force) force=1; shift ;;
		--) shift; break ;;
	esac done

	[[ $# -ne 1 ]] && error "$PROGRAM $COMMAND [--recursive,-r] [--force,-f] pass-name" Usage
	local path="$1"
	check_paths "$path"

	if [[ ! -d "$CRYPT_PATH/$path" ]]; then
		path=$(check_file "$path" noask)
		[[ $? -eq 0 ]] || exit 1
		[[ -z "$path" ]] && error "$1 not found in the crypt"
	fi

	local dir="$CRYPT_PATH/${path%/}"
	local file="$CRYPT_PATH/$path.gpg"

	[[ -f $file && -d $dir && $path == */ || ! -f $file ]] && file="${dir%/}/"
	[[ -e $file ]] || error "$path is not in the crypt."
	git_prep "$file"

	[[ $force -eq 1 ]] || confirm "Are you sure you would like to delete $path?"

	rm $recursive -f -v "$file"
	git_prep "$file"
	if [[ ! -e $file ]]; then
		git -C "$INNER_GIT_DIR" rm -qr "$file"
		git_prep "$file"
		git_commit "Remove $path from crypt."
	fi
	rmdir -p "${file%/*}" 2>/dev/null
}

cmd_copy_move() {
	[[ $# -ne 2 ]] && error "$PROGRAM $COMMAND old-path new-path" Usage
	[[ $CLOSED -eq 1 ]] && error "The crypt must be open to $COMMAND a file."

	check_paths "$1" "$2"
	local old_path="${1%/}"

	if [[ ! -d "$CRYPT_PATH/$old_path" ]]; then
		old_path=$(check_file "$old_path" noask)
		[[ $? -eq 0 ]] || exit 1
		[[ -z "$old_path" ]] && error "$1 not found in the crypt"
	fi
	old_path="$CRYPT_PATH/${old_path%.gpg}"

	local ext="${entries_ext[$(find_entry "$old_path")]}"
	[[ -n $ext ]] && ext=".$ext"

	local old_dir="$old_path"
	local new_path="$CRYPT_PATH/$2"
	[[ -d "$new_path" || "$new_path" == *$'/' ]] || new_path="${new_path%$ext}$ext"

	[[ "$new_path" == *.gpg ]] && error "Ambiguous extension for $2"

	if ! [[ -f $old_path.gpg && -d $old_path && $1 == */ || ! -f $old_path.gpg ]]; then
		old_dir="${old_path%/*}"
		old_path="${old_path}.gpg"
	fi
	[[ -e $old_path ]] || error "$1 is not in the crypt."

	mkdir -p -v "${new_path%/*}"
	[[ -d $old_path || -d $new_path || $new_path == */ ]] || new_path="${new_path}.gpg"

	local interactive="-i"
	[[ ! -t 0 ]] && interactive="-f"

	git_prep "$new_path"
	if [[ $COMMAND == "move" || $COMMAND == "mv" ]]; then
		mv $interactive -v "$old_path" "$new_path" || exit 1
		[[ -e "$new_path" ]] && reencrypt_path "$new_path"

		git_prep "$new_path"
		if [[ -n $INNER_GIT_DIR && ! -e $old_path ]]; then
			git -C "$INNER_GIT_DIR" rm -qr "$old_path" 2>/dev/null
			git_prep "$new_path"
			git_track "$new_path" "Move \`$1\` to \`$2\`."
		fi
		git_prep "$old_path"
		if [[ -n $INNER_GIT_DIR && ! -e $old_path ]]; then
			git -C "$INNER_GIT_DIR" rm -qr "$old_path" 2>/dev/null
			git_prep "$old_path"
			[[ -n $(git -C "$INNER_GIT_DIR" status --porcelain "$old_path") ]] && git_commit "Remove ${1}."
		fi
		rmdir -p "$old_dir" 2>/dev/null
	elif [[ $COMMAND == "copy" || $COMMAND == "cp" ]]; then
		cp $interactive -r -v "$old_path" "$new_path" || exit 1
		[[ -e "$new_path" ]] && reencrypt_path "$new_path"
		git_track "$new_path" "Copy \`$1\` to \`$2\`."
	fi
}

_cmd_list_fmt() {
	read -a tmp <<< "$1"
	local path=${tmp[-1]}

	local name="$(basename -- "$path")"
	local entry=$(find_entry "$path") entry_name=""

	# FIXME: color1 screws up in the tree view sometimes
	local color1="" reset1="" color2="" reset2=""
	if [ $entry -eq 2 ]; then
		color1="$(_color "${entries_color[$entry]}")"
		[ -z "${entries_color[$entry]}" ] || reset1="$(_color reset)"
	else
		color2="$(_color "${entries_color[$entry]}")"
		[ -z "${entries_color[$entry]}" ] || reset2="$(_color reset)"
		entry_name="${entries_name[$entry]}"

		# Add the icon for signed files
		[[ -f "$path.sig" ]] && reset2="$reset2 🔑"
	fi

	local tmp=${name%*.${entries_ext[$entry]}.gpg}
	[ -z tmp ] || name=$tmp

	sed "s~$path~$color1$name$reset1\t\v$color2$entry_name$reset2~" <<< "$1"
}

cmd_list() {
	local opts plain=0
	opts="$($GETOPT -o p -l plain -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do
		case $1 in
			-p|--plain) plain=1; shift ;;
			--)           shift; break ;;
		esac
	done

	[[ $# -gt 1 ]] && error "$PROGRAM $COMMAND [--plain] [subdir]" Usage

	local path="$CRYPT_PATH/${1#$CRYPT_PATH}"
	[[ -d "$path" ]] || error "Given path does not exist"

	if [ $plain -eq 0 ]; then
		local header="Crypt ($PRETTY_PATH)"
		[[ $CLOSED -eq 1 ]] && printf "%s\n%s\n" "$header" "$(_color gray,bold)Closed 🔒$(_color reset)" && return

		if [[ -n "$1" && "$1" != $CRYPT_PATH ]]; then
			local color="" reset=""
			color=$(_color ${entries_color[2]})
			reset=$(_color reset)
			header="$color$1$reset"
		fi

		echo "$header"
		tree -f --noreport -l "$path" "${args[@]}" -I '*.sig' | tail -n +2 | while IFS='' read -r line; do _cmd_list_fmt "$line"; done | \
		column -t -s$'\t' | sed 's/\v/\t\t/' # Make pretty columns
	else
		local tmp=$(find "$path" -path '*/.git' -prune -o -path '*/.extensions' -prune -o -iname '*.gpg' -print | \
			sed -e "s~^$path\/*~~" | sort | while IFS='' read -r line; do \
			local i=$(find_entry "$line"); echo "${line%.gpg} ${entries_name[$i]} ${line%.${entries_ext[$i]}.gpg}"; done)

		# XXX: Highly inefficient...
		local reps=$(echo "$tmp" | uniq -D -f 2)
		echo "$tmp" | comm --nocheck-order -23 - <(echo "$reps") | awk '{print $3"\t"$2}'
		[ -z "$reps" ] || echo "$reps" | awk '{print $1"\t"$2}'
	fi
}

cmd_git() {
	git_prep "$CRYPT_PATH/"
	[[ -n $INNER_GIT_DIR ]] || error "git repository is missing. Try to reinitialize the crypt."
	make_tmpdir nowarn
	export TMPDIR="$SECURE_TMPDIR"
	git -C "$INNER_GIT_DIR" "$@"
}

cmd_grep() {
	[[ $# -lt 1 ]] && error "$PROGRAM $COMMAND [GREPOPTIONS] search-string" Usage
	[[ $CLOSED -eq 1 ]] && error "The crypt must be open to use $COMMAND."

	local file results
	while read -r -d "" file; do
		results="$($GPG -d "${GPG_OPTS[@]}" "$file" | grep --color=always "$@")"
		[[ $? -ne 0 ]] && continue
		file="${file%.gpg}"
		file="${file#$CRYPT_PATH/}"
		echo "$(_color cyan,bold)$file$(_color reset):"
		echo "$results"
	done < <(find -L "$CRYPT_PATH" -path '*/.git' -prune -o -path '*/.extensions' -prune -o -iname '*.gpg' -print0)
}

cmd_sign() {
	local opts verify=0 remove=0
	opts="$($GETOPT -o v,r -l verify,remove -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-v|--verify) verify=1; shift ;;
		-r|--remove) remove=1; shift ;;
		--) shift; break ;;
	esac done

	[[ $verify -eq 1 && $remove -eq 1 ]] && error "$PROGRAM $COMMAND [--verify|--remove] [files]" Usage
	[[ -n "$CRYPT_SIGNING_KEY" ]] || error "No signing key was specified!"
	[[ -d "$CRYPT_PATH" ]] || error "Try to initialize the crypt."

	local loaded=0 files=()
	if [[ $# -eq 0 ]]; then
		[[ $verify -eq 1 ]] || error "$PROGRAM $COMMAND [--verify|--remove] [files]" Usage
		readarray -t files < <(find "$CRYPT_PATH/" -path '*/.git' -prune -o -path "$CRYPT_PATH/*.sig" -print)
	else
		for path in "$@"; do
			local path="$CRYPT_PATH/${path%/}"
			path="${path%.sig}"
			check_paths "$path"
			[ -f "$path" ] || path="$path.gpg"

			if [ ! -f "$path" ]; then
				# If it fails, try loading .entries
				if [[ $loaded -eq 0 ]]; then
					load_entries "$CRYPT_PATH/.entries"
					loaded=1
				fi

				path="$CRYPT_PATH/$(check_file "$path" noask)"
				[[ $? -ne 0 || -z $path ]] && exit 1
				[ -f "$path" ] || path="$path.gpg"
				[ -f "$path" ] || error "$1 not found in crypt."
			fi
			files+=( "$path" )
		done
	fi

	if [[ $verify -eq 1 ]]; then
		printf "Verifying signature(s) for the keys:\n$(_color white,bold)%s$(_color reset)\n\n" "$CRYPT_SIGNING_KEY"
		for f in "${files[@]}"; do
			gpg_verify "${f%.sig}" && echo "${f#$CRYPT_PATH/}: $(_color green)Valid ✔️$(_color reset)"
		done
	elif [[ $remove -eq 1 ]]; then
		for f in "${files[@]}"; do
			local file="${f%.sig}.sig"
			[[ ! -f "$file" ]] && echo "${f%.sig} is not signed!" && continue

			rm -f -v "$file"
			git_prep "$file"

			if [[ ! -e $file ]]; then
				git -C "$INNER_GIT_DIR" rm -qr "$file"
				git_prep "$file"
				git_commit "Remove $f signature from crypt."
			fi
		done
	else
		printf "Signing with the keys:\n$(_color white,bold)%s$(_color reset)\n\n" "$CRYPT_SIGNING_KEY"
		for f in "${files[@]}"; do
			git_prep "$f.sig"
			gpg_sign "$f" && echo "$(_color green)$f signed successfully$(_color reset)"
			git -C "$INNER_GIT_DIR" add "$f" # update file
			git_track "$f.sig" "Signing \`$f\` with $CRYPT_SIGNING_KEY."
		done
	fi
}

cmd_open() {
	local file="$CRYPT_PATH/$CRYPT_ARCHIVE"
	[[ $CLOSED -eq 1 ]] || error "Crypt already open."

	gpg_verify "$file"
	$GPG -d "${GPG_OPTS[@]}" "$file" 2>/dev/null | tar x -C $CRYPT_PATH || error "Failed to open the archive."

	mv -f $file $file.old >/dev/null 2>&1
	mv -f $file.sig $file.sig.old >/dev/null 2>&1
	echo "Crypt successfully opened at $PRETTY_PATH"
}

cmd_close() {
	local file="$CRYPT_PATH/$CRYPT_ARCHIVE"
	[[ $CLOSED -eq 1 ]] && error "Crypt already closed."

	touch $file $file.sig
	gpg_recipients "$CRYPT_PATH"

	tar c --exclude ".gpg-id" --exclude "$CRYPT_ARCHIVE.old" --exclude ".extensions" --exclude ".gpg-id.sig" \
	--exclude "$CRYPT_ARCHIVE.sig.old" --exclude "$CRYPT_ARCHIVE" --exclude "$CRYPT_ARCHIVE.sig" -C $CRYPT_PATH . | \
	"$GPG" -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file" "${GPG_OPTS[@]}" 2>&1 >/dev/null || error "Failed to archive the crypt."

	gpg_sign "$file"

	# TODO Fix permissions
	#chmod 400 "$file"
	#chmod 400 "$file.sig" 2>/dev/null

	echo "The crypt has been closed, cleaning up old data..."
	rm -rf $file.old $file.sig.old

	shred_data() {
		find "$CRYPT_PATH/" -mindepth 1 -maxdepth 1 -not \( -name '.extensions' -o -name '.gpg-id' -or -name '.gpg-id.sig' \
			-or -name '.crypt.tar.gpg*' \) -exec rm -rf {} +
	}
	trap shred_data EXIT
}

cmd_help() {
	cat <<-EOF
		Usage:
		    $PROGRAM init gpg-id...
		        Initialize the crypt at \$CRYPT_PATH using the given GPG key(s).

		    $PROGRAM open
		        Open the crypt, extracting the content of the $CRYPT_ARCHIVE file.

		    $PROGRAM close
		        Close the crypt, creating the $CRYPT_ARCHIVE file.

		    $PROGRAM [show] file
		        Show the file using the entry's associated show_action.

		    $PROGRAM insert file
		        Insert the file using the entry's associated insert_action.

		    $PROGRAM edit file
		        Edit the file using the entry's associated edit_action.

		    $PROGRAM list [--plain] [subdir]
		        List the crypt structure, associating each file to its entry name.

		    $PROGRAM grep [GREPOPTIONS] search-string
		        Run grep with GREPOPTIONS and search-string.

		    $PROGRAM info
		        List the loaded entries and other information for the crypt.

		    $PROGRAM sign [--verify|--remove] [files]
		        Sign (or verify the signature of) a file file or the whole crypt.
		        Uses the key(s) in \$CRYPT_SIGNING_KEY for the signatures.

		    $PROGRAM git git-args...
		        Run git commands with the crypt repository.

		    $PROGRAM move old-path new-path
		        Move a file from old-path to new-path.

		    $PROGRAM copy old-path new-path
		        Copy a file from old-path to new-path.

		    $PROGRAM remove path [-fr]
		        Remove a file or directory.

		    $PROGRAM version
		        Show version information.

		    $PROGRAM help
		        Show this text.
	EOF
}

cmd_version() {
	echo "crypt v0.1"
	echo "Made by Federico Angelilli <mail@fedang.net>"
}

# MAIN
PRETTY_PATH="${CRYPT_PATH/#\/home\/$USER/\~}"
PROGRAM="${0##*/}"
COMMAND="$1"

[[ ! -f "$CRYPT_PATH/$CRYPT_ARCHIVE" ]]
CLOSED=$?

[[ "$COMMAND" != sign && "$COMMAND" != init ]] && load_entries "$CRYPT_PATH/.entries" && load_extensions

case "$COMMAND" in
	help|--help) shift; cmd_help "$@" ;;
	version|--version) shift; cmd_version "$@" ;;
	close) shift; cmd_close "$@" ;;
	open) shift; cmd_open "$@" ;;
	sign) shift; cmd_sign "$@" ;;
	git) shift; cmd_git "$@" ;;
	init) shift; cmd_init "$@" ;;
	info) shift; cmd_info "$@" ;;
	edit) shift; cmd_edit "$@" ;;
	insert) shift; cmd_insert "$@" ;;
	show) shift; cmd_show "$@" ;;
	grep) shift; cmd_grep "$@" ;;
	list|ls) shift; cmd_list "$@" ;;
	move|mv) shift; cmd_copy_move "$@" ;;
	copy|cp) shift; cmd_copy_move "$@" ;;
	remove|rm) shift; cmd_remove "$@" ;;
	*) cmd_show "$@" ;;
esac
exit 0

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

CRYPT_PATH="${CRYPT_PATH:-~/.crypt}"
CRYPT_EXTENSION="${CRYPT_EXTENSION:-$CRYPT_PATH/.extensions}"

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
	git_commit "$2"
}

git_commit() {
	[[ -n $INNER_GIT_DIR ]] || error "git repository is missing. Try to reinitialize the crypt."
	git -C "$INNER_GIT_DIR" commit -m "$1"
}

git_init() {
	INNER_GIT_DIR="$CRYPT_PATH"
	git -C "$INNER_GIT_DIR" init || exit 1
	git_track "$CRYPT_PATH" "Add current contents."

	echo '*.gpg diff=gpg' > "$CRYPT_PATH/.gitattributes"
	git_track '.gitattributes' "Configure git for gpg file diff."

	touch "$CRYPT_PATH/.entries"
	git_track '.entries' "Add \`.entries\` file."

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
	[[ -f $1.sig ]] || error "Signature for $1 does not exist."
	local fingerprints="$($GPG $CRYPT_GPG_OPTS --verify --status-fd=1 "$1.sig" "$1" 2>/dev/null | sed -n 's/^\[GNUPG:\] VALIDSIG \([A-F0-9]\{40\}\) .* \([A-F0-9]\{40\}\)$/\1\n\2/p')"
	local fingerprint found=0
	for fingerprint in $CRYPT_SIGNING_KEY; do
		[[ $fingerprint =~ ^[A-F0-9]{40}$ ]] || continue
		[[ $fingerprints == *$fingerprint* ]] && { found=1; break; }
	done
	[[ $found -eq 1 ]] || error "Signature for $1 is invalid."
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

# Unknown entry @unknown
entries_ext+=( "" )
entries_name+=( "unknown" )
entries_insert+=( "none" )
entries_show+=( "none" )
entries_edit+=( "none" )
entries_color+=( "gray" )

# Unencrypted entry
entries_ext+=( "" )
entries_name+=( "unencrypted !" )
entries_insert+=( "none" )
entries_show+=( "none" )
entries_edit+=( "none" )
entries_color+=( "white,bold" )

# Directory entry
entries_ext+=( "" )
entries_name+=( "" )
entries_insert+=( "none" )
entries_show+=( "none" )
entries_edit+=( "none" )
entries_color+=( "blue,bold" )

# Undefined action
function none() { echo "$(_color red,bold)No action specified$(_color reset)"; }

load_entries() {
	gpg_verify "$1"

	while IFS= read -r line; do
		readarray -t arr < <(awk -v FPAT='(\"([^\"]|\\\\")*\"|[^[:space:]\"])+'  '{for (i=1; i<=NF; i++) print $i}' <<< $line)
		declare -A opts=( ["name"]="none" ["edit_action"]="none" ["insert_action"]="none" ["show_action"]="none" ["color"]="none" ["entry"]="none" )

		for w in "${arr[@]:1}"; do
			IFS='=' read -r k v <<< "$w"
			opts["$k"]="${v:-none}"
			[[ "${opts[$k]}" == $'"'* ]] && opts["$k"]="${opts[$k]:1:-1}" # Strip quotes
		done

		local i
		case "${arr[0]}" in
			\@unknown) i=0 ;;
			\@unencrypted) i=1 ;;
			\@directory) i=2 ;;
			\@entry) i="${#entries_name[@]}" ;;
			*) error "Unexpected entry" ;;
		esac

		entries_ext[$i]="${opts[extension]}"
		entries_name[$i]="${opts[name]}"
		entries_insert[$i]="${opts[insert_action]}"
		entries_show[$i]="${opts[show_action]}"
		entries_edit[$i]="${opts[edit_action]}"
		entries_color[$i]="${opts[color]}"

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
	elif [[ "$path" != *.gpg ]]; then
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
	[[ -f "$CRYPT_PATH/$path.gpg" ]] && echo "$path" && return

	local matches=()
	for ((i = 3; i < ${#entries_name[@]}; i++)); do
		readarray -t -O ${#matches[@]} matches < <(find "$CRYPT_PATH/" -path '*/.git' -prune -o -path "$CRYPT_PATH/${path%/}.${entries_ext[$i]}.gpg" -print)
	done

	case ${#matches[@]} in
		0) [[ "$2" == "noask" ]] || confirm_file "$path" ;;
		1) [[ "${matches[0]}" =~ $CRYPT_PATH/(.*)\.gpg ]] && echo "${BASH_REMATCH[1]}" ;;
		*) error "Ambiguous entry name: $(echo "${matches[@]}" | sed "s~$CRYPT_PATH/\([^[:space:]]*\).gpg~\1~g")" ;;
	esac
}

confirm_file() {
	local entry=$(find_entry "${1%.gpg}.gpg") ans=""
	[[ ($entry -eq 0 && ${#entries_ext[@]} -eq 3) || $entry -eq 1 ]] && echo "$1" && return

	while true; do
		for ((i = 3; i < ${#entries_name[@]}; i++)); do
			echo "${entries_ext[$i]}) $(_color ${entries_color[$i]})${entries_name[$i]}$(_color reset)" >&2
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
	for ((i = 0; i < ${#entries_name[@]}; i++)); do
		echo "Entry #$i"
		echo "Name: '${entries_name[$i]}'"
		echo "Ext: '${entries_ext[$i]}'"
		echo "Edit: '${entries_edit[$i]}'"
		echo "Show: '${entries_show[$i]}'"
		echo "Insert: '${entries_insert[$i]}'"

		local reset="" color=""
		color=$(_color ${entries_color[$i]})
		[ -z "$color" ] || reset=$(_color reset)
		printf "Color: '%s%s%s'\n\n" $color "${entries_color[$i]}" $reset
	done

	echo "${#entries_name[@]} entries in $(cd $CRYPT_PATH; dirs +0)/.entries"
}

cmd_init() {
	[[ $# -lt 1 ]] && error "$PROGRAM $COMMAND gpg-id..." Usage

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

		if [[ -n $CRYPT_SIGNING_KEY ]]; then
			local signing_keys=( ) key
			for key in $CRYPT_SIGNING_KEY; do
				signing_keys+=( --default-key $key )
			done

			$GPG "${GPG_OPTS[@]}" "${signing_keys[@]}" --detach-sign "$gpg_id" || error "Could not sign .gpg_id."
			key="$($GPG "${GPG_OPTS[@]}" --verify --status-fd=1 "$gpg_id.sig" "$gpg_id" 2>/dev/null | sed -n 's/^\[GNUPG:\] VALIDSIG [A-F0-9]\{40\} .* \([A-F0-9]\{40\}\)$/\1/p')"
			[[ -n $key ]] || error "Signing of .gpg_id unsuccessful."
			git_track "$gpg_id.sig" "Signing new GPG id with ${key//[$IFS]/,}."

			local entries="$CRYPT_PATH/.entries"
			$GPG "${GPG_OPTS[@]}" "${signing_keys[@]}" --detach-sign "$entries" || error "Could not sign .entries."
			key="$($GPG "${GPG_OPTS[@]}" --verify --status-fd=1 "$entries.sig" "$entries" 2>/dev/null | sed -n 's/^\[GNUPG:\] VALIDSIG [A-F0-9]\{40\} .* \([A-F0-9]\{40\}\)$/\1/p')"
			[[ -n $key ]] || error "Signing of .entries unsuccessful."
			git_track "$entries.sig" "Signing .entries with ${key//[$IFS]/,}."
		fi
	fi

	reencrypt_path "$CRYPT_PATH/"
	git_track "$CRYPT_PATH/" "Reencrypt crypt using new GPG id ${id_print%, }."
}

_cmd_edit_file() {
	local path="$1" file="$CRYPT_PATH/$path.gpg"
	git_prep "$file"

	[[ -d $file ]] && error "Path is a directory"
	[[ "$2" == insert && -e $file ]] && confirm "An entry already exists for $path. Overwrite it?"

	mkdir -p -v "$CRYPT_PATH/$(dirname -- "$path")"
	gpg_recipients "$(dirname -- "$path")"

	local entry=$(find_entry "$file")

	make_tmpdir
	local tmp_file="$(mktemp -u "$SECURE_TMPDIR/XXXXXX")-${path//\//-}"

	local what="Insert"
	if [[ -f $file && "$2" != insert ]]; then
		$GPG -d -o "$tmp_file" "${GPG_OPTS[@]}" "$file" || exit 1
		what="Update"
	fi

	local action=none
	case $2 in
		insert) action="${entries_insert[$entry]}" ;;
		edit) action="${entries_edit[$entry]}" ;;
		show) action="${entries_show[$entry]}" ;;
	esac

	eval "$action" "$tmp_file"
	[[ -f $tmp_file ]] || error "File not saved."

	$GPG -d -o - "${GPG_OPTS[@]}" "$file" 2>/dev/null | diff - "$tmp_file" &>/dev/null && \
	([[ "$2" != edit ]] || echo "File unchanged.") && return

	while ! $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file" "${GPG_OPTS[@]}" "$tmp_file"; do
		confirm "GPG encryption failed. Would you like to try again?"
	done

	# XXX: Sometimes this gets a namespec error, why?
	git_track "$file" "$what ${entries_name[$entry]} entry \`$path\`."
}


cmd_insert() {
	[[ $# -ne 1 ]] && error "$PROGRAM $COMMAND entry" Usage

	local path="${1%/}"
	check_paths "$path"
	path=$(confirm_file "$path")
	_cmd_edit_file "$path" insert
}

cmd_edit() {
	[[ $# -ne 1 ]] && error "$PROGRAM $COMMAND file" Usage

	local path="${1%/}"
	check_paths "$path"
	path=$(check_file "$path")
	_cmd_edit_file "$path" edit
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

	local dir="$CRYPT_PATH/${path%/}"
	local file="$CRYPT_PATH/$path.gpg"

	[[ -f $file && -d $dir && $path == */ || ! -f $file ]] && file="${dir%/}/"
	[[ -e $file ]] || error "$path is not in the password store."
	git_prep "$file"

	[[ $force -eq 1 ]] || confirm "Are you sure you would like to delete $path?"

	rm $recursive -f -v "$file"
	git_prep "$file"
	if [[ -n $INNER_GIT_DIR && ! -e $file ]]; then
		git -C "$INNER_GIT_DIR" rm -qr "$file"
		git_prep "$file"
		git_commit "Remove $path from store."
	fi
	rmdir -p "${file%/*}" 2>/dev/null
}

_cmd_list_fmt() {
	read -a tmp <<< "$@"
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
	fi

	local tmp=${name%*.${entries_ext[$entry]}}
	[ -z tmp ] || name=$tmp

	sed "s~$path~$color1${name%.gpg}$reset1\t\v$color2$entry_name$reset2~" <<< "$@"
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

	local path="$CRYPT_PATH/${1#$CRYPT_PATH}"

	if [ $plain -eq 0 ]; then
		local header="Crypt ($(cd $CRYPT_PATH; dirs +0))"

		if [[ -n "$1" && "$1" != $CRYPT_PATH ]]; then
			local color="" reset=""
			# DIR ENTRY 2
			color=$(_color ${entries_color[2]})
			reset=$(_color reset)
			header="$color$1$reset"
		fi

		echo "$header"
		tree -f --noreport -l "$path" | tail -n +2 | while IFS='' read -r line; do _cmd_list_fmt "$line"; done | \
		column -t -s$'\t' | sed 's/\v/\t\t/' # Make pretty columns
	else
		local tmp=$(find "$path" -type f -iname '*.gpg' | sed -e "s~^$path\/*~~" | sort | \
			while IFS='' read -r line; do local i=$(find_entry "$line"); echo "${line%.gpg} ${entries_name[$i]} ${line%.${entries_ext[$i]}.gpg}"; done)

		local reps=$(echo "$tmp" | uniq -D -f 2)

		# XXX: Highly inefficient...
		echo "$tmp" | comm -23 - <(echo "$reps") | awk '{print $3" "$2}'
		echo "$reps" | awk '{print $1" "$2}'
	fi
}

cmd_git() {
	git_prep "$CRYPT_PATH/"
	[[ -n $INNER_GIT_DIR ]] || error "git repository is missing. Try to reinitialize the crypt."
	make_tmpdir nowarn
	export TMPDIR="$SECURE_TMPDIR"
	git -C "$INNER_GIT_DIR" "$@"
}

cmd_show() {
	local path="$1"
	check_paths "$path"

	if [[ -d $CRYPT_PATH/$path ]]; then
		[[ -z $path ]] && path="$CRYPT_PATH"
		cmd_list "$path"
	else
		path="${1%/}"
		path=$(check_file "${path%.gpg}" noask)
		[[ $? -eq 0 ]] || exit 1

		if [[ -z "$path" ]]; then
			error "$1 not found in the crypt"
		elif [[ -f "$CRYPT_PATH/$path.gpg" ]]; then
			_cmd_edit_file "$path" show
		else
			error "Try to initialize the crypt"
		fi
	fi
}

cmd_copy_move() {
	[[ $# -ne 2 ]] && error "$PROGRAM $COMMAND old-path new-path" Usage

	check_paths "$1" "$2"
	local old_path="$CRYPT_PATH/${1%/}"
	old_path="${old_path%.gpg}"
	local old_dir="$old_path"
	local new_path="$CRYPT_PATH/$2"

	[[ "$new_path" == *.gpg ]] && error "Ambiguous extension for $2"

	if ! [[ -f $old_path.gpg && -d $old_path && $1 == */ || ! -f $old_path.gpg ]]; then
		old_dir="${old_path%/*}"
		old_path="${old_path}.gpg"
	fi
	[[ -e $old_path ]] || error "$1 is not in the password store."

	mkdir -p -v "${new_path%/*}"
	[[ -d $old_path || -d $new_path || $new_path == */ ]] || new_path="${new_path}.gpg"

	local interactive="-i"
	[[ ! -t 0 ]] && interactive="-f"

	git_prep "$new_path"
	if [[ $COMMAND == "move" ]]; then
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
	else
		cp $interactive -r -v "$old_path" "$new_path" || exit 1
		[[ -e "$new_path" ]] && reencrypt_path "$new_path"
		git_track "$new_path" "Copy \`$1\` to \`$2\`."
	fi
}

cmd_grep() {
	[[ $# -lt 1 ]] && error "$PROGRAM $COMMAND [GREPOPTIONS] search-string" Usage
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

cmd_verify() {
	# TODO: Verify all the signatures in the crypt
	[[ $# -gt 1 ]] && error "$PROGRAM $COMMAND [file]" Usage
	[[ -n $CRYPT_SIGNING_KEY ]] || error "No signing key was specified!"

	printf "Verifying signatures for the keys:\n$(_color white,bold)%s$(_color reset)\n\n" "$CRYPT_SIGNING_KEY"

	[[ $# -eq 1 ]] && gpg_verify "$1" && return

	for f in ".gpg-id" ".entries"; do
		echo "Checking signature for $f:"
		gpg_verify "$CRYPT_PATH/$f" && echo "$(_color green)Valid$(_color reset)"
	done
}

cmd_help() {
	cat <<-EOF
		Usage:
		    $PROGRAM init gpg-id...
		        Initialize the crypt at \$CRYPT_PATH

		    $PROGRAM [show] file
		        Show the file using the entry's associated show_action

		    $PROGRAM insert file
		        Insert the file using the entry's associated insert_action

		    $PROGRAM edit file
		        Edit the file using the entry's associated edit_action

		    $PROGRAM list [--plain]
		        List the crypt structure, associating each file to its entry name

		    $PROGRAM grep [GREPOPTIONS] search-string
		        Run grep with GREPOPTIONS and search-string

		    $PROGRAM info
		        List the crypt registered entries

		    $PROGRAM verify [file]
		        Verify the signature associated with a file or the crypt

		    $PROGRAM git git-args...
		        Run git commands

		    $PROGRAM move old-path new-path
		        Move a file from old-path to new-path

		    $PROGRAM copy old-path new-path
		        Copy a file from old-path to new-path

		    $PROGRAM remove path [-fr]
		        Remove a file or directory

		    $PROGRAM help
		        Show this text

		    $PROGRAM version
		        Show version information
	EOF
}

cmd_version() {
	echo "crypt v0"
}

# MAIN
PROGRAM="${0##*/}"
COMMAND="$1"

[[ "$COMMAND" != init && "$COMMAND" != verify && "$COMMAND" != open ]] && load_entries "$CRYPT_PATH/.entries"

# TODO: What to do with unencrypted files???

case "$COMMAND" in
	help|--help) shift; cmd_help "$@" ;;
	version|--version) shift; cmd_version "$@" ;;

	# IDEA FOR CLOSE AND OPEN
	# basically when you open the crypt (which is a tar.gz.gpg) a ramfs/tmpfs is created and the
	# archive is put there, then it mounted to the crypt path, and modification are only in memory
	# then when you close the thing is closed and created an updated archive
	# maybe it is not needed since everything is encrypted. idk

	#close|lock) ;;
	#open|unlock) ;;

	verify) shift; cmd_verify "$@" ;;
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

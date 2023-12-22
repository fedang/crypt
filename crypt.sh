#!/usr/bin/env bash

umask 077
set -o pipefail

CRYPT_PATH="${CRYPT_PATH:-~/.crypt}"

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
	echo "$@" >&2
	exit 1
}

confirm() {
	[[ -t 0 ]] || return 0
	local ans
	read -r -p "$1 [y/N] " ans
	[[ $ans == [yY] ]] || exit 1
}

# GIT HANDLING
unset GIT_DIR GIT_WORK_TREE GIT_NAMESPACE GIT_INDEX_FILE GIT_INDEX_VERSION GIT_OBJECT_DIRECTORY GIT_COMMON_DIR
export GIT_CEILING_DIRECTORIES="$CRYPT_PATH/.."

git_prep() {
	INNER_GIT_DIR="${1%/*}"
	while [[ ! -d $INNER_GIT_DIR && ${INNER_GIT_DIR%/*}/ == "${CRYPT_PATH%/}/"* ]]; do
		INNER_GIT_DIR="${INNER_GIT_DIR%/*}"
	done
	[[ $(git -C "$INNER_GIT_DIR" rev-parse --is-inside-work-tree 2>/dev/null) == true ]] || \
	error "Error: git repository is missing. It seems like crypt was not initialized properly."
}

git_track() {
	[[ -n $INNER_GIT_DIR ]] || \
	error "Error: git repository is missing. It seems like crypt was not initialized properly."
	git -C "$INNER_GIT_DIR" add "$1" || return
	[[ -n $(git -C "$INNER_GIT_DIR" status --porcelain "$1") ]] || return
	git_commit "$2"
}

git_commit() {
	[[ -n $INNER_GIT_DIR ]] || \
	error "Error: git repository is missing. It seems like crypt was not initialized properly."
	git -C "$INNER_GIT_DIR" commit -m "$1"
}

git_init() {
	INNER_GIT_DIR="$CRYPT_PATH"
	git -C "$INNER_GIT_DIR" init || exit 1
	git_track "$CRYPT_PATH" "Add current contents."

	echo '*.gpg diff=gpg' > "$CRYPT_PATH/.gitattributes"
	git_track '.gitattributes' "Configure git for gpg file diff."

	touch "$CRYPT_PATH/.entries"
	git_track '.entries' "Add .entries file."

	git -C "$INNER_GIT_DIR" config --local diff.gpg.binary true
	git -C "$INNER_GIT_DIR" config --local diff.gpg.textconv "$GPG -d ${GPG_OPTS[*]}"
}

# ENCRYPTION
GPG_OPTS=( $CRYPT_GPG_OPTS "--quiet" "--yes" "--compress-algo=none" "--no-encrypt-to" )
GPG="gpg"
export GPG_TTY="${GPG_TTY:-$(tty 2>/dev/null)}"
command -v gpg2 &>/dev/null && GPG="gpg2"
[[ -n $GPG_AGENT_INFO || $GPG == "gpg2" ]] && GPG_OPTS+=( "--batch" "--use-agent" )

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

	[[ ! -f $current ]] && \
	error "Error: gpg-id is missing. It seems like crypt was not initialized properly."

	local gpg_id
	while read -r gpg_id; do
		gpg_id="${gpg_id%%#*}" # strip comment
		[[ -n $gpg_id ]] || continue

		GPG_RECIPIENT_ARGS+=( "-r" "$gpg_id" )
		GPG_RECIPIENTS+=( "$gpg_id" )
	done < "$current"
}

sneaky_path() {
	local path
	for path in "$@"; do
		[[ $path =~ /\.\.$ || $path =~ ^\.\./ || $path =~ /\.\./ || $path =~ ^\.\.$ ]] \
		&& error "Error: You have passed a sneaky path..."
	done
}

tmpdir() {
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
	done < <(find "$1" -path '*/.git' -prune -o -name '*.extensions' -prune -o -iname '*.gpg' -print0)
}

# FILE INFO

# Entries
entries_glob=()
entries_name=()
entries_insert=()
entries_show=()
entries_edit=()
entries_color=()

# Unknown entry
entries_glob+=( "@unknown" )
entries_name+=( "unknown" )
entries_insert+=( "none" )
entries_show+=( "none" )
entries_edit+=( "none" )
entries_color+=( "gray" )

# Unencrypted entry
entries_glob+=( "@unencrypted" )
entries_name+=( "unencrypted !" )
entries_insert+=( "none" )
entries_show+=( "none" )
entries_edit+=( "none" )
entries_color+=( "white,bold" )

# Directory entry FIXME
entries_glob+=( "@directory" )
entries_name+=( "" )
entries_insert+=( "none" )
entries_show+=( "none" )
entries_edit+=( "none" )
entries_color+=( "blue,bold" )

# Rules
rules_glob=()
rules_entry=()
rules_color=()

# Undefined action
function none() { echo "$(_color red,bold)No action specified$(_color reset)"; }

load_info() {
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
			\@entry) i="${#entries_glob[@]}" ;;
			*)	# RULES
				i="${#rules_glob[@]}";
				rules_glob[$i]="${arr[0]}";
				rules_entry[$i]=0
				for ((j = 3; j < ${#entries_name[@]}; j++)); do
					if [[ "${opts[entry]}" == ${entries_name[j]} ]]; then
						rules_entry[$i]=$j
					fi
				done
				rules_color[$i]="${opts[color]}"
				continue
				;;
		esac

		entries_glob[$i]="*.${opts[extension]}"
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

find_info() {
	# Current file info
	file_glob=""
	file_entry=""
	file_insert=""
	file_show=""
	file_edit=""
	file_color1=""
	file_color2=""

	# Find entry
	local path="${1#$CRYPT_PATH/}" entry=0
	if [ -d "$CRYPT_PATH/$path" ]; then
		entry=2
	elif [[ "$path" != *.gpg ]]; then
		entry=1
	else
		for ((i = 3; i < ${#entries_glob[@]}; i++)); do
			if [[ "${path%.gpg}" == ${entries_glob[$i]} ]]; then
				entry=$i
				break
			fi
		done
	fi

	file_glob=${entries_glob[$entry]}
	file_entry=${entries_name[$entry]}
	file_insert=${entries_insert[$entry]}
	file_show=${entries_show[$entry]}
	file_edit=${entries_edit[$entry]}

	# TODO: Fix ad hoc handling
	if [[ $entry -eq 2 ]]; then
		file_color1=${entries_color[$entry]}
		return
	else
		file_color2=${entries_color[$entry]}
	fi

	# Find rules
	for ((i = 0; i < ${#rules_glob[@]}; i++)); do
		if [[ "${path%.gpg}" == ${rules_glob[$i]} ]]; then
			if [[ ${rules_entry[$i]} -ne 0 ]]; then
				entry=${rules_entry[$i]}
				file_glob=${rules_glob[$entry]}
				file_entry=${entries_name[$entry]}
				file_insert=${entries_insert[$entry]}
				file_show=${entries_show[$entry]}
				file_edit=${entries_edit[$entry]}
				file_color2=${entries_color[$entry]}
			fi
			file_color1=${rules_color[$i]}
		fi
	done
}

# Expects a non-directory path
check_file() {
	local path="${1#$CRYPT_PATH/}"
	[[ -f "$path.gpg" ]] && echo "$path" && return

	local matches=()
	for ((i = 3; i < ${#entries_glob[@]}; i++)); do
		readarray -t -O ${#matches[@]} matches < <(find "$CRYPT_PATH/" -maxdepth 1 -path '*/.git' -prune -o -path "$CRYPT_PATH/${path%/}${entries_glob[$i]}.gpg" -print)
	done

	#printf "%q\n" "${matches[@]}" >&2
	case ${#matches[@]} in
		0) confirm_file "$path" ;;
		1) [[ "${matches[0]}" =~ $CRYPT_PATH/(.*)\.gpg ]] && echo "${BASH_REMATCH[1]}" ;;
		*) error "Ambiguous entry name: ${matches[@]}" ;;
	esac
}

confirm_file() {
	local ans="$1"
	while true; do
		[[ "$ans" == *.gpg ]] && echo "Ambiguous extension!" >&2
		find_info "$ans"
		[[ ("$file_entry" != "unknown" || ${#entries_glob[@]} -eq 3) && "$file_entry" != "unencrypted" ]] && echo "$ans" && return
		# TODO: Make something that given the entry name automatically appends the extension
		read -r -p "Enter a file with a valid extension: " ans
	done
}

# COMMANDS
GETOPT="getopt"
SHRED="shred -f -z"

cmd_info() {
	for ((i = 0; i < ${#entries_name[@]}; i++)); do
		echo "Entry #$i"
		echo "Name: '${entries_name[$i]}'"
		echo "Glob: '${entries_glob[$i]}'"
		echo "Edit: '${entries_edit[$i]}'"
		echo "Show: '${entries_show[$i]}'"
		echo "Insert: '${entries_insert[$i]}'"

		local reset="" color=""
		color=$(_color ${entries_color[$i]})
		[ -z "$color" ] || reset=$(_color reset)
		printf "Color: '%s%s%s'\n\n" $color "${entries_color[$i]}" $reset
	done

	for ((i = 0; i < ${#rules_glob[@]}; i++)); do
		echo "Rule #$i"
		echo "Glob: '${rules_glob[$i]}'"
		echo "Entry: '${rules_entry[$i]}'"

		local reset="" color=""
		color=$(_color ${rules_color[$i]})
		[ -z "$color" ] || reset=$(_color reset)
		printf "Color: '%s%s%s'\n\n" $color "${rules_color[$i]}" $reset
	done
}

cmd_init() {
	[[ $# -lt 1 ]] && error "Usage: $PROGRAM $COMMAND gpg-id..."

	mkdir -v -p "$CRYPT_PATH/"
	git_init

	local gpg_id="$CRYPT_PATH/.gpg-id"
	git_prep "$gpg_id"

	if [[ $# -eq 1 && -z $1 ]]; then
		[[ ! -f "$gpg_id" ]] && \
		error "Error: $gpg_id does not exist and therefore it cannot be removed."

		rm -v -f "$gpg_id" || exit 1
		git -C "$INNER_GIT_DIR" rm -qr "$gpg_id"
		git_commit "Deinitialize $gpg_id."
		rmdir -p "${gpg_id%/*}" 2>/dev/null
	else
		printf "%s\n" "$@" > "$gpg_id"
		local id_print="$(printf "%s, " "$@")"
		echo "Crypt initialized for ${id_print%, }"
		git_track "$gpg_id" "Set GPG id to ${id_print%, }."
	fi

	reencrypt_path "$CRYPT_PATH/"
	git_track "$CRYPT_PATH/" "Reencrypt crypt using new GPG id ${id_print%, }."
}

cmd_insert() {
	[[ $# -ne 1 ]] && error "Usage: $PROGRAM $COMMAND [--force,-f] entry"

	local path="${1%/}"
	sneaky_path "$path"
	path=$(confirm_file $path)

	local file="$CRYPT_PATH/$path.gpg"
	git_prep "$file"

	[[ -e $file ]] && confirm "An entry already exists for $path. Overwrite it?"

	mkdir -p -v "$CRYPT_PATH/$(dirname -- "$path")"
	gpg_recipients "$(dirname -- "$path")"

	find_info "$file"

	# TODO: Make function to do the edit boilerplate

	tmpdir
	local tmp_file="$(mktemp -u "$SECURE_TMPDIR/XXXXXX")-${path//\//-}"

	eval "$file_insert" "$tmp_file"
	[[ -f $tmp_file ]] || error "New file not saved."

	while ! $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file" "${GPG_OPTS[@]}" "$tmp_file"; do
		confirm "GPG encryption failed. Would you like to try again?"
	done
	git_track "$file" "Add $file_entry entry $path."
}

cmd_edit() {
	[[ $# -ne 1 ]] && error "Usage: $PROGRAM $COMMAND file"

	local path="${1%/}"
	sneaky_path "$path"
	path=$(check_file "$path")
	echo $path

	mkdir -p -v "$CRYPT_PATH/$(dirname -- "$path")"
	gpg_recipients "$(dirname -- "$path")"

	local file="$CRYPT_PATH/$path.gpg"
	[[ -d $file ]] && error "Path is a directory"
	git_prep "$file"

	tmpdir
	local tmp_file="$(mktemp -u "$SECURE_TMPDIR/XXXXXX")-${path//\//-}.txt"

	local action="Add"
	if [[ -f $file ]]; then
		$GPG -d -o "$tmp_file" "${GPG_OPTS[@]}" "$file" || exit 1
		action="Edit"
	fi

	find_info "$file"

	eval "$file_edit" "$tmp_file"
	[[ -f $tmp_file ]] || error "New file not saved."

	$GPG -d -o - "${GPG_OPTS[@]}" "$file" 2>/dev/null | diff - "$tmp_file" &>/dev/null && echo "File unchanged." && return
	while ! $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file" "${GPG_OPTS[@]}" "$tmp_file"; do
		confirm "GPG encryption failed. Would you like to try again?"
	done
	git_track "$file" "$action $file_entry entry $path."
}


_cmd_list_fmt() {
	read -a tmp <<< "$@"
	local path=${tmp[-1]}

	local name="$(basename -- "$path")"
	find_info "$path"

	local color1="$(_color $file_color1)" reset1=""
	[ -z "$file_color1" ] || reset1="$(_color reset)"

	local color2="$(_color $file_color2)" reset2=""
	[ -z "$file_color2" ] || reset2="$(_color reset)"

	sed "s~$path~$color1${name%$file_glob.gpg}$reset1\t\v$color2$file_entry$reset2~" <<< "$@"
}

cmd_list() {
	local path="$CRYPT_PATH/${1#$CRYPT_PATH}"
	local header="Crypt ($(cd $CRYPT_PATH; dirs +0))"

	if [ -n "$1" ]; then
		local color="" reset=""
		# DIR ENTRY 2
		color=$(_color ${entries_color[2]})
		reset=$(_color reset)
		header="$color$1$reset"
	fi

	echo "$header"
	tree -f --noreport -l "$path" | tail -n +2 | while IFS='' read -r line; do _cmd_list_fmt "$line"; done | \
	column -t -s$'\t' | sed 's/\v/\t\t/' # Make pretty columns
}

cmd_git() {
	git_prep "$CRYPT_PATH/"
	[[ -n $INNER_GIT_DIR ]] || \
	error "Error: git repository is missing. It seems like crypt was not initialized properly."

	tmpdir nowarn
	export TMPDIR="$SECURE_TMPDIR"
	git -C "$INNER_GIT_DIR" "$@"
}

cmd_show() {
	local path="$1"
	sneaky_path "$path"

	if [[ -d $CRYPT_PATH/$path ]]; then
		[[ -z $path ]] && path="$CRYPT_PATH"
		cmd_list "$path"
	else
		path=$(check_file $path)
		[[ $? -eq 0 ]] || exit 1

		local file="$CRYPT_PATH/${path%.gpg}.gpg"
		if [[ -f $file ]]; then
			mkdir -p -v "$CRYPT_PATH/$(dirname -- "$path")"
			gpg_recipients "$(dirname -- "$path")"

			git_prep "$file"

			tmpdir
			local tmp_file="$(mktemp -u "$SECURE_TMPDIR/XXXXXX")-${path//\//-}.txt"

			$GPG -d -o "$tmp_file" "${GPG_OPTS[@]}" "$file" || exit 1

			find_info "$file"

			eval "$file_show" "$tmp_file"
			[[ -f $tmp_file ]] || error "New file not saved."

			$GPG -d -o - "${GPG_OPTS[@]}" "$file" 2>/dev/null | diff - "$tmp_file" &>/dev/null && return

			while ! $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file" "${GPG_OPTS[@]}" "$tmp_file"; do
				confirm "GPG encryption failed. Would you like to try again?"
			done
			git_track "$file" "Update $file_entry entry $path."

		elif [[ -z $path ]]; then
			error "Error: crypt is empty. Try initializing it first."
		else
			error "Error: $path is not in the crypt."
		fi
	fi
}

cmd_maybe_show() {
	# TODO options
	if [[ $# -eq 0 ]]; then
		cmd_list
	else
		cmd_show "$@"
	fi
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

		    $PROGRAM list
				List the crypt structure, associating each file to its entry name

		    $PROGRAM info
				List the crypt registered entries

		    $PROGRAM git git-args...
				Run git commands

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

[ -f "$CRYPT_PATH/.entries" ] && load_info "$CRYPT_PATH/.entries"

case "$COMMAND" in
	help|--help) shift; cmd_help "$@" ;;
	version|--version) shift; cmd_version "$@" ;;

	#close|lock) ;;
	#open|unlock) ;;
	#check|verify) ;; #SIGNATURE
	#vcs) ;;

	git) shift; cmd_git "$@" ;;
	init) shift; cmd_init "$@" ;;
	info) shift; cmd_info "$@" ;;
	edit) shift; cmd_edit "$@" ;;
	insert) shift; cmd_insert "$@" ;;
	list) shift; cmd_list "$@" ;;
	show) shift; cmd_show "$@" ;;
	*) cmd_maybe_show "$@" ;;
esac
exit 0

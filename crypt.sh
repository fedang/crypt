#!/usr/bin/env bash
#
# Copy to /usr/bin/crypt

umask 077
set -o pipefail

GPG_OPTS=( $CRYPT_GPG_OPTS "--quiet" "--yes" "--compress-algo=none" "--no-encrypt-to" )
GPG="gpg"
export GPG_TTY="${GPG_TTY:-$(tty 2>/dev/null)}"
command -v gpg2 &>/dev/null && GPG="gpg2"
[[ -n $GPG_AGENT_INFO || $GPG == "gpg2" ]] && GPG_OPTS+=( "--batch" "--use-agent" )

LOCATION="${CRYPT_LOCATION:-$HOME/.crypt}"

unset GIT_DIR GIT_WORK_TREE GIT_NAMESPACE GIT_INDEX_FILE GIT_INDEX_VERSION GIT_OBJECT_DIRECTORY GIT_COMMON_DIR
export GIT_CEILING_DIRECTORIES="$LOCATION/.."

error() {
	echo "$@" >&2
	exit 1
}

confirm() {
	[[ -t 0 ]] || return 0
	local inp
	read -r -p "$1 [y/N] " inp
	[[ $inp == [yY] ]] || exit 1
}

git_prep() {
	INNER_GIT_DIR="${1%/*}"
	while [[ ! -d $INNER_GIT_DIR && ${INNER_GIT_DIR%/*}/ == "${LOCATION%/}/"* ]]; do
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
	INNER_GIT_DIR="$LOCATION"
	git -C "$INNER_GIT_DIR" init || exit 1
	git_track "$LOCATION" "Add current contents."

	touch "$LOCATION/.info"
	git_track '.info' "Add .info file."

	cat <<-EOF > "$LOCATION/.ignore"
	.git*
	.info
	.ignore
	EOF
	git_track '.ignore' "Add .ignore file."

	echo '*.gpg diff=gpg' > "$LOCATION/.gitattributes"
	git_track '.gitattributes' "Configure git for gpg file diff."

	git -C "$INNER_GIT_DIR" config --local diff.gpg.binary true
	git -C "$INNER_GIT_DIR" config --local diff.gpg.textconv "$GPG -d ${GPG_OPTS[*]}"
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

	local current="$LOCATION/$1"
	while [[ $current != "$LOCATION" && ! -f $current/.gpg-id ]]; do
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
		file_dir="${file_dir#$LOCATION}"
		file_dir="${file_dir#/}"
		local file_display="${file#$LOCATION/}"
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

confirm_kind() {
	[[ $1 == *.pass || $1 == *.otp || $1 == *.txt ]] && echo "$1" && return

	for kind in "pass" "otp" "txt"; do
		[[ -f "$LOCATION/$1.$kind.gpg" ]] && echo "$1.$kind" && return
	done

	local inp kind=""
	while true; do
		read -r -p $'Select which kind of entry you want.\n1) pass\n2) otp\n3) txt\n' inp
		case "$inp" in
			pass|pas|password|1) kind='pass'; break ;;
			otp|2fa|2) 			 kind='otp';  break ;;
			text|txt|3) 		 kind='txt';  break ;;
		esac
	done
	echo "$1.$kind"
}

urlencode() {
	local l=${#1}
	for (( i = 0 ; i < l ; i++ )); do
		local c=${1:i:1}
		case "$c" in
			[a-zA-Z0-9.~_-]) printf "%c" "$c";;
			' ') printf + ;;
			*) printf '%%%.2X' "'$c"
		esac
	done
}

urldecode() {
	local url_encoded="${1//+/ }"
	printf '%b' "${url_encoded//%/\\x}"
}

otp_uri() {
	local uri="$1"

	uri="${uri//\`/%60}"
	uri="${uri//\"/%22}"

	local pattern='^otpauth:\/\/(totp|hotp)(\/(([^:?]+)?(:([^:?]*))?)(:([0-9]+))?)?\?(.+)$'
	[[ "$uri" =~ $pattern ]] || error "Cannot parse OTP key URI: $uri"

	otp_uri=${BASH_REMATCH[0]}
	otp_type=${BASH_REMATCH[1]}
	otp_label=${BASH_REMATCH[3]}

	otp_accountname=$(urldecode "${BASH_REMATCH[6]}")
	[[ -z $otp_accountname ]] && otp_accountname=$(urldecode "${BASH_REMATCH[4]}") || otp_issuer=$(urldecode "${BASH_REMATCH[4]}")
	[[ -z $otp_accountname ]] && error "Invalid key URI (missing accountname): $otp_uri"

	local p=${BASH_REMATCH[9]}
	local params
	local IFS=\&; read -r -a params < <(echo "$p") ; unset IFS

	pattern='^([^=]+)=(.+)$'
	for param in "${params[@]}"; do
		if [[ "$param" =~ $pattern ]]; then
			case ${BASH_REMATCH[1]} in
				secret) otp_secret=${BASH_REMATCH[2]} ;;
				digits) otp_digits=${BASH_REMATCH[2]} ;;
				algorithm) otp_algorithm=${BASH_REMATCH[2]} ;;
				period) otp_period=${BASH_REMATCH[2]} ;;
				counter) otp_counter=${BASH_REMATCH[2]} ;;
				issuer) otp_issuer=$(urldecode "${BASH_REMATCH[2]}") ;;
				*) ;;
			esac
		fi
	done

	[[ -z "$otp_secret" ]] && error "Invalid key URI (missing secret): $otp_uri"

	pattern='^[0-9]+$'
	[[ "$otp_type" == 'hotp' ]] && [[ ! "$otp_counter" =~ $pattern ]] && \
	error "Invalid key URI (missing counter): $otp_uri"
}

BASE64="base64"
SHRED="shred -f -z"
GETOPT="getopt"
OATH=$(which oathtool)

cmd_init() {
	[[ $# -lt 1 ]] && error "Usage: $PROGRAM $COMMAND gpg-id..."

	mkdir -v -p "$LOCATION/"
	git_init

	local gpg_id="$LOCATION/.gpg-id"
	git_prep "$gpg_id"

	if [[ $# -eq 1 && -z $1 ]]; then
		[[ ! -f "$gpg_id" ]] && \
		error"Error: $gpg_id does not exist and therefore it cannot be removed."

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

	reencrypt_path "$LOCATION/"
	git_track "$LOCATION/" "Reencrypt crypt using new GPG id ${id_print%, }."
}

cmd_add() {
	local opts noecho=1 force=0
	opts="$($GETOPT -o ef -l echo,force -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do
		case $1 in
			-e|--echo) noecho=0; shift ;;
			-f|--force) force=1; shift ;;
			--)           shift; break ;;
		esac
	done

	[[ $err -ne 0 || $# -ne 1 ]] && error "Usage: $PROGRAM $COMMAND [--echo,-e] [--force,-f] entry"
	local path="${1%/}"
	sneaky_path "$path"
	path=$(confirm_kind $path)

	local file="$LOCATION/$path.gpg"
	git_prep "$file"

	[[ $force -eq 0 && -e $file ]] && confirm "An entry already exists for $path. Overwrite it?"

	mkdir -p -v "$LOCATION/$(dirname -- "$path")"
	gpg_recipients "$(dirname -- "$path")"

	local kind
	case "$path" in
		*.pass)
			kind="password"
			if [[ $noecho -eq 1 ]]; then
				local pass1 pass2
				while true; do
					read -r -p "Enter password for $path: " -s pass1 || exit 1
					echo
					read -r -p "Retype password for $path: " -s pass2 || exit 1
					echo
					if [[ "$pass1" == "$pass2" ]]; then
						echo "$pass1" | $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file" "${GPG_OPTS[@]}" || \
						error "Password encryption aborted."
						break
					else
						error "Error: the entered passwords do not match."
					fi
				done
			else
				local pass
				read -r -p "Enter password for $path: " -e pass
				echo "$pass" | $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file" "${GPG_OPTS[@]}" || \
				error "Password encryption aborted."
			fi ;;
		*.otp)
			kind="otp"
			local code
			read -r -p "Enter otp code for $path: " -e code
			echo "$code" | $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file" "${GPG_OPTS[@]}" || \
			error "File encryption aborted."
			;;
		*.txt)
			kind="text"
			tmpdir
			local tmp_file="$(mktemp -u "$SECURE_TMPDIR/XXXXXX")-${path//\//-}"

			local action="Add"
			${EDITOR:-vi} "$tmp_file"
			[[ -f $tmp_file ]] || error "New file not saved."
			while ! $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file" "${GPG_OPTS[@]}" "$tmp_file"; do
				confirm "GPG encryption failed. Would you like to try again?"
			done
			;;
		*) error "Internal error" ;;
	esac

	git_track "$file" "Add $kind entry $path."
}

cmd_list() {
	local opts notree=0
	opts="$($GETOPT -o n -l no-tree -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do
		case $1 in
			-n|--no-tree) notree=1; shift ;;
			--)           shift; break ;;
		esac
	done

	local path="$LOCATION/${1#$LOCATION}"

	if [[ $notree -eq 0 ]]; then
		echo "${1:-Crypt ($(cd $LOCATION; dirs +0))}"
		local ignore=""
		[[ -f "$LOCATION/.ignore" ]] && ignore="--gitfile=$LOCATION/.ignore"
		TREE_COLORS="rs=0:di=01;34:ln=01;36:" tree "$path" --noreport -C -l -N $ignore --info | \
		sed "/ -> /d;s/\.txt.gpg$/\t$(tput setaf 1)text$(tput sgr0)/;s/\.pass.gpg$/\t$(tput setaf 3)password$(tput sgr0)/;s/\.otp.gpg$/\t$(tput setaf 2)otp$(tput sgr0)/" | \
		column -t -s$'\t' | tail -n +2
	else
		local path2=$(echo $path | sed 's/\//\\\//g')
		find "$path" -type f -iname '*.gpg' | sed "s/.gpg$//;s/^$path2\/*//"
	fi
}

cmd_show() {
	local path="$1"
	sneaky_path "$path"
	path=$(confirm_kind $path)

	local file="$LOCATION/$path.gpg"

	if [[ -f $file ]]; then
		case "$path" in
			*.pass)
				local pass
				pass="$($GPG -d "${GPG_OPTS[@]}" "$file" | $BASE64)" || exit $?
				echo "$pass" | $BASE64 -d
				;;
			*.otp)
				[[ -z "$OATH" ]] && error "Error: oathtool is not installed."

  				local contents=$($GPG -d "${GPG_OPTS[@]}" "$file")
  				while read -r line; do
					if [[ "$line" == otpauth://* ]]; then
					  	local uri="$line"
					  	otp_uri "$line"
					  	break
					fi
  				done < <(echo "$contents")

  				local cmd
  				case "$otp_type" in
					totp)
  				    	cmd="$OATH -b --totp"
  				    	[[ -n "$otp_algorithm" ]] && cmd+=$(echo "=${otp_algorithm}"|tr "[:upper:]" "[:lower:]")
  				    	[[ -n "$otp_period" ]] && cmd+=" --time-step-size=$otp_period"s
  				    	[[ -n "$otp_digits" ]] && cmd+=" --digits=$otp_digits"
  				    	cmd+=" $otp_secret"
  				    	;;

  				  	hotp)
						local counter=$((otp_counter + 1))
						cmd="$OATH -b --hotp --counter=$counter"
						[[ -n "$otp_digits" ]] && cmd+=" --digits=$otp_digits"
						cmd+=" $otp_secret"
						;;

  				  	*)
  				    	error "$path: OTP secret not found."
					;;
  				esac

  				local out; out=$($cmd) || error "$path: failed to generate OTP code."

  				if [[ "$otp_type" == "hotp" ]]; then
					local line replaced uri=${otp_uri/&counter=$otp_counter/&counter=$counter}
					while IFS= read -r line; do
					  [[ "$line" == otpauth://* ]] && line="$uri"
					  [[ -n "$replaced" ]] && replaced+=$'\n'
					  replaced+="$line"
					done < <(echo "$contents")

					otp_insert "$path" "$file" "$replaced" "Increment HOTP counter for $path." "$quiet"
				fi
				echo "$out"
				;;
			*.txt)
				$GPG -d "${GPG_OPTS[@]}" "$file"
				;;
			*) error "Unsupported entry kind" ;;
		esac
	elif [[ -d $LOCATION/$path ]]; then
		local treepath="$path"
		[[ -z $path ]] && treepath="$LOCATION"
		cmd_list "$treepath"
	elif [[ -z $path ]]; then
		error "Error: crypt is empty. Try initializing it first."
	else
		error "Error: $path is not in the crypt."
	fi
}

cmd_edit() {
	[[ $# -ne 1 ]] && error "Usage: $PROGRAM $COMMAND file"

	local path="${1%/}"
	sneaky_path "$path"

	path=$(confirm_kind "$path")

	mkdir -p -v "$LOCATION/$(dirname -- "$path")"
	gpg_recipients "$(dirname -- "$path")"

	local file="$LOCATION/$path.gpg"
	git_prep "$file"

	tmpdir
	local tmp_file="$(mktemp -u "$SECURE_TMPDIR/XXXXXX")-${path//\//-}.txt"

	local action="Add"
	if [[ -f $file ]]; then
		$GPG -d -o "$tmp_file" "${GPG_OPTS[@]}" "$file" || exit 1
		action="Edit"
	fi
	${EDITOR:-vi} "$tmp_file"
	[[ -f $tmp_file ]] || error "New file not saved."
	$GPG -d -o - "${GPG_OPTS[@]}" "$file" 2>/dev/null | diff - "$tmp_file" &>/dev/null && error "File unchanged."
	while ! $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$file" "${GPG_OPTS[@]}" "$tmp_file"; do
		confirm "GPG encryption failed. Would you like to try again?"
	done
	git_track "$file" "$action $path using ${EDITOR:-vi}."
}

cmd_info() {
	[[ $# -ne 0 ]] && error "Usage: $PROGRAM $COMMAND"
	local file="$LOCATION/.info"
	git_prep "$file"
	${EDITOR:-vi} "$file"
	git_track "$file" "Update .info file."
}

cmd_git() {
	git_prep "$LOCATION/"
	[[ -n $INNER_GIT_DIR ]] || \
	error "Error: git repository is missing. It seems like crypt was not initialized properly."

	tmpdir nowarn
	export TMPDIR="$SECURE_TMPDIR"
	git -C "$INNER_GIT_DIR" "$@"
}

cmd_maybe_show() {
	if [[ $# -eq 0 || ($# -eq 1 && $1 == "--no-tree") ]]; then
		cmd_list "$@"
	else
		cmd_show "$@"
	fi
}

cmd_help() {
	cat <<-EOF
		Usage:
		    $PROGRAM init gpg-id...

		    $PROGRAM [subfolder]

		    $PROGRAM [show] file

		    $PROGRAM add file

		    $PROGRAM edit file

		    $PROGRAM info

		    $PROGRAM git git-args...

		    $PROGRAM help
		        Show this text

		    $PROGRAM version
		        Show version information
	EOF
}

cmd_version() {
	echo "crypt v0"
}

PROGRAM="${0##*/}"
COMMAND="$1"

case "$1" in
	init) shift; cmd_init "$@" ;;
	add) shift; cmd_add "$@" ;;
	show) shift; cmd_show "$@" ;;
	edit) shift; cmd_edit "$@" ;;
	info) shift; cmd_info "$@" ;;
	git) shift; cmd_git "$@" ;;
	list) shift; cmd_list "$@" ;;
	help|--help) shift; cmd_help "$@" ;;
	version|--version) shift; cmd_version "$@" ;;
	*) cmd_maybe_show "$@" ;;
esac
exit 0


# Bash completion
#
# Copy to /usr/share/bash-completion/completions/crypt

# TODO: edit & other actions
_crypt() {
	COMPREPLY=()

	local location="${CRYPT_PATH:-$HOME/.crypt}"
	location="${location%/}/"
	local cur="${COMP_WORDS[COMP_CWORD]}"

	local IFS=$'\n'
	local suffix=".gpg"

	local firstitem=""
	local i=0 item
	local items=($(compgen -f $location$cur))

	for item in ${items[@]}; do
		[[ $item =~ /\.[^/]*$ ]] && continue

		if [[ ${#items[@]} -eq 1 ]]; then
			while [[ -d $item ]]; do
				local subitems=($(compgen -f "$item/"))
				local filtereditems=( ) item2
				for item2 in "${subitems[@]}"; do
					[[ $item2 =~ /\.[^/]*$ ]] && continue
					filtereditems+=( "$item2" )
				done
				if [[ ${#filtereditems[@]} -eq 1 ]]; then
					item="${filtereditems[0]}"
				else
					break
				fi
			done
		fi

		[[ -d $item ]] && item="$item/"

		item="${item%$suffix}"
		COMPREPLY+=("${item#$location}")
		if [[ $i -eq 0 ]]; then
			firstitem=$item
		fi
		let i+=1
	done

	if [[ $i -gt 1 || ( $i -eq 1 && -d $firstitem ) ]]; then
		compopt -o nospace
	fi
}

complete -o filenames -F _crypt crypt

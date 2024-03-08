#compdef crypt
#autoload

# copy to /usr/share/zsh/site-functions/_crypt

# TODO: edit & other actions
_crypt() {
	local IFS=$'\n'
	local location
	zstyle -s ":completion:${curcontext}:" location location || location="${CRYPT_PATH:-$HOME/.crypt}"
	_values -C 'entries' ${$(crypt list --plain 2>/dev/null | sed -e "s#\([^[:space:]]*\)[[:space:]]*\(.*\)#\1\[\2\]#g" | sort):-""}
}

_crypt

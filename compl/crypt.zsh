#compdef crypt
#autoload

# copy to /usr/share/zsh/site-functions/_crypt

_crypt() {
	local IFS=$'\n'
	local location
	zstyle -s ":completion:${curcontext}:" location location || location="${CRYPT_PATH:-$HOME/.crypt}"
	_values -C 'entries' ${$(crypt list --plain | sed -e "s#\([^[:space:]]*\)[[:space:]]*\(.*\)#\1\[\2\]#g" | sort):-""}
}

_crypt

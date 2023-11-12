#compdef crypt
#autoload

_crypt() {
	local IFS=$'\n'
	local location
	zstyle -s ":completion:${curcontext}:" location location || location="${CRYPT_LOCATION:-$HOME/.crypt}"
	_values -C 'entries' ${$(find -L "$location" -name '*.gpg' -type f -print 2>/dev/null | sed -e "s#${location}/\{0,1\}##" -e 's#\.gpg##' -e 's#\\#\\\\#g' -e 's#:#\\:#g' -e 's/\.\(pass\|otp\|txt\)/\[\1\]/' | sort):-""}
}

_crypt

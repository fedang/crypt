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

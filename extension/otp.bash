_otp_parse() {
	urldecode() {
		local url_encoded="${1//+/ }"
		printf '%b' "${url_encoded//%/\\x}"
	}

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
OATH=$(which oathtool)

otp_code() {
	[[ -z "$OATH" ]] && error "oathtool is required by otp_code action."

	while read -r line; do
		if [[ "$line" == otpauth://* ]]; then
			uri="$line"
			_otp_parse "$line"
			break
		fi
	done < "$FILE"

	local cmd
	case "$otp_type" in
		totp) cmd="$OATH -b --totp"
			[[ -n "$otp_algorithm" ]] && cmd+=$(echo "=${otp_algorithm}" | tr "[:upper:]" "[:lower:]")
			[[ -n "$otp_period" ]] && cmd+=" --time-step-size=$otp_period"s
			[[ -n "$otp_digits" ]] && cmd+=" --digits=$otp_digits"
			cmd+=" $otp_secret"
			;;

		hotp)
			counter=$((otp_counter + 1))
			cmd="$OATH -b --hotp --counter=$counter"
			[[ -n "$otp_digits" ]] && cmd+=" --digits=$otp_digits"
			cmd+=" $otp_secret"
			;;

		*) error "OTP secret not found." ;;
	esac

	eval "$cmd" || error "Failed to generate OTP code."

	if [[ "$otp_type" == "hotp" ]]; then
		local line replaced uri=${otp_uri/&counter=$otp_counter/&counter=$counter}
		while IFS= read -r line; do
		  [[ "$line" == otpauth://* ]] && line="$uri"
		  [[ -n "$replaced" ]] && replaced+=$'\n'
		  replaced+="$line"
		done < "$FILE"

		echo "$replaced" > "$FILE"
		MESSAGE="Increment HOTP counter for $NAME."
	fi
}

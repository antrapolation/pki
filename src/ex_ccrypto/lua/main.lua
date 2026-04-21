local pkey = require("openssl").pkey

function gen_ec_keypair(curve)
	local tcurve = curve or "prime256v1"

	local kid = pkey.new("ec", tcurve)
	local priv = pkey.export(kid, "der", false)
	local pkid = pkey.get_public(kid)
	local pub = pkey.export(pkid, "der", false)

	return priv, pub
end

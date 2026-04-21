defmodule ExCcrypto.X509.CertProfile.ValidityDateError do
  defexception message: "Validity date is not in correct format"
end

defmodule ExCcrypto.X509.CertProfile.SubjectMandatoryFieldMissing do
  defexception message: "Subject mandatory field is not given"
end

# Public Struct
defmodule ExCcrypto.X509.CertProfile do
  require X509.ASN1
  alias ExCcrypto.Keypair
  alias ExCcrypto.X509.CertProfile.SubjectMandatoryFieldMissing
  alias ExCcrypto.X509.X509Certificate
  alias ExCcrypto.X509.CertProfile

  require Logger

  use Timex

  @type key_usage_const ::
          :digital_signature
          | :non_repudiation
          | :key_encipherment
          | :data_encipherment
          | :key_agreement
          | :key_cert_sign
          | :crl_sign
          | :encipher_only
          | :decipher_only

  @type ext_key_usage_const ::
          :all_purpose
          | :server_auth
          | :client_auth
          | :code_signing
          | :email_protection
          | :timestamping
          | :ocsp_signing

  @type cert_validity :: %{
          not_before: DateTime.t(),
          not_after: DateTime.t()
        }

  @type external_signer :: %{
          callback: fun(cert_in_der :: binary(), digest_name :: atom(), options :: List.t()),
          key_algo: :ecdsa
        }

  @type validity_unit :: :year | :month | :day | :hour | :min
  @type cert_validity_pack :: {pos_integer(), validity_unit()}

  use TypedStruct

  typedstruct do
    field(:is_issuer, boolean(), default: false)
    # this is incorrect as cert_path_length = 0 means this is the last CA 
    # To be a valid root, this value must not be set.
    # Or it should be set to 0 if this is the last CA.
    # field(:cert_path_length, non_neg_integer(), default: 0)
    field(:cert_path_length, any())
    field(:serial, binary() | tuple(), default: {:random, 8})
    field(:key_usage, list(key_usage_const()))
    field(:ext_key_usage, list(ext_key_usage_const()))
    field(:issuer_cert, tuple())
    field(:issuer_key, tuple())
    field(:self_sign, boolean(), default: false)
    field(:inc_subject_key_id, boolean(), default: true)
    field(:inc_auth_key_id, boolean(), default: true)
    field(:crl_dist_point, list(), default: [])
    # aia
    field(:ocsp_url, list(), default: [])
    # aia
    field(:issuer_url, list(), default: [])
    # aia
    field(:timestamping_url, list(), default: [])
    # aia
    field(:ca_repository_url, list(), default: [])
    field(:hash, atom(), default: :sha384)
    field(:valid_from, tuple())
    field(:valid_until, tuple())
    field(:validity, cert_validity_pack(), default: {2, :year})
    field(:validity_timezone, String.t(), default: "Etc/UTC")
    # field :validity_timezone, String.t(), default: "Asia/Kuala_Lumpur"
    # final result to read when sent to cert generation
    field(:cert_validity, cert_validity(), default: %{not_before: nil, not_after: nil})
    # issued cert not_after cannot be same or after not_after of the issuer 
    # this is the min gap
    # i.e. if issuer not_after is 20 June 2088, cert issued not_after cannot be after 20 May 2088
    field(:issued_cert_min_validity_gap, tuple(), default: {1, :month})
    field(:cert_gen_callback, fun())

    field(:cert_chain, list(), default: [])
  end

  @spec self_sign_issuer_cert_config(binary()) ::
          %CertProfile{}
  def self_sign_issuer_cert_config(issuer_key \\ nil)

  def self_sign_issuer_cert_config(issuer_key) do
    %CertProfile{
      %CertProfile{}
      | is_issuer: true,
        key_usage: [
          :digital_signature,
          :non_repudiation,
          :key_cert_sign,
          :crl_sign
        ],
        # ext_key_usage: [:ocsp_signing],
        # OCSP should not be tie back to root
        ext_key_usage: [],
        validity: {25, :year},
        self_sign: true,
        issuer_key: issuer_key
    }
  end

  def cert_profile_type(%CertProfile{is_issuer: true, self_sign: true}), do: :self_sign_issuer
  def cert_profile_type(%CertProfile{is_issuer: true, self_sign: false}), do: :issuer

  def cert_profile_type(%CertProfile{is_issuer: false, self_sign: true}),
    do: :self_sign_non_issuer

  def cert_profile_type(%CertProfile{is_issuer: false, self_sign: false}), do: :subscriber

  @spec issuer_cert_config(
          Keypair.key_pack() | external_signer(),
          X509.ASN1.otp_certificate()
        ) ::
          %CertProfile{}
  def issuer_cert_config(issuer_key \\ nil, issuer_cert \\ nil) do
    %CertProfile{
      %CertProfile{}
      | is_issuer: true,
        key_usage: [:digital_signature, :non_repudiation, :key_cert_sign, :crl_sign],
        # ext_key_usage: [:ocsp_signing],
        # No need to put as default
        ext_key_usage: [],
        validity: {20, :year},
        self_sign: false,
        issuer_key: issuer_key,
        issuer_cert: issuer_cert
    }
  end

  @spec self_sign_leaf_cert_config(binary()) ::
          %CertProfile{}
  def self_sign_leaf_cert_config(user_key \\ nil) do
    %CertProfile{
      %CertProfile{}
      | is_issuer: false,
        key_usage: [:digital_signature, :non_repudiation, :key_agreement],
        ext_key_usage: [],
        validity: {1, :year},
        self_sign: true,
        issuer_key: user_key
    }
  end

  @spec leaf_cert_config(
          Keypair.key_pack() | external_signer(),
          X509.ASN1.otp_certificate()
        ) ::
          %CertProfile{}
  def leaf_cert_config(issuer_key \\ nil, issuer_cert \\ nil) do
    %{
      %CertProfile{}
      | is_issuer: false,
        key_usage: [:digital_signature, :non_repudiation, :key_agreement],
        ext_key_usage: [],
        validity: {2, :year},
        self_sign: false,
        issuer_key: issuer_key,
        issuer_cert: issuer_cert
    }
  end

  def self_sign_tls_server_cert_config(user_key \\ nil) do
    config = self_sign_leaf_cert_config(user_key)

    %{
      config
      | ext_key_usage: config.ext_key_usage ++ [:server_auth, :client_auth]
    }
  end

  def tls_server_cert_config(issuer_key \\ nil, issuer_cert \\ nil) do
    config = leaf_cert_config(issuer_key, issuer_cert)
    %{config | ext_key_usage: config.ext_key_usage ++ [:server_auth, :client_auth]}
  end

  def tls_client_cert_config(issuer_key \\ nil, issuer_cert \\ nil) do
    config = leaf_cert_config(issuer_key, issuer_cert)
    %{config | ext_key_usage: config.ext_key_usage ++ [:client_auth]}
  end

  def set_signing_key(nil, _) do
    {:error, :cert_profile_struct_is_expected_but_got_nil}
  end

  def set_signing_key(_, nil) do
    {:error, :signing_key_is_empty}
  end

  def set_signing_key(config, signingKey) do
    %CertProfile{config | issuer_key: signingKey}
  end

  def set_signer_cert(nil, _) do
    {:error, :cert_profile_struct_is_expected_but_got_nil}
  end

  def set_signer_cert(_, nil) do
    {:error, :signer_cert_is_empty}
  end

  def set_signer_cert(config, {format, _} = cert) do
    case format do
      :native ->
        %CertProfile{config | issuer_cert: cert}

      _ ->
        set_signer_cert(config, X509Certificate.to_native!(cert))
    end
  end

  def set_signer_cert(config, cert) do
    %CertProfile{config | issuer_cert: cert}
  end

  @spec set_key_usage(%CertProfile{}, [] | :atom) :: %CertProfile{}
  def set_key_usage(config, ku) when is_list(ku) do
    %{config | key_usage: ku}
  end

  def set_key_usage(config, ku) do
    %{config | key_usage: [ku | config.key_usage]}
  end

  def set_ext_key_usage(config, eku) when is_list(eku) do
    %{config | ext_key_usage: eku}
  end

  def set_ext_key_usage(config, eku) do
    %{config | ext_key_usage: [eku | config.ext_key_usage]}
  end

  def set_signing_hash(config, hash) do
    %{config | hash: hash}
  end

  def set_serial(config, serial) do
    %{config | serial: serial}
  end

  # @spec set_validity(CertProfile.t(), tuple(), tuple(), String.t()) ::
  #        CertProfile.t()
  def set_validity(
        config,
        {{_, _, _}, {_, _, _}} = valid_from,
        {{_, _, _}, {_, _, _}} = valid_to,
        timezone \\ "Etc/UTC"
      ) do
    %CertProfile{
      config
      | valid_from: valid_from,
        valid_until: valid_to,
        validity_timezone: timezone,
        cert_validity: %{
          config.cert_validity
          | not_before: Timex.to_datetime(valid_from, timezone),
            not_after: Timex.to_datetime(valid_to, timezone)
        },
        # this is important to stop the loop down there
        validity: nil
    }
  end

  @spec set_validity_period(
          %CertProfile{},
          :now | NaiveDateTime.t(),
          cert_validity_pack(),
          String.t()
        ) ::
          %CertProfile{}
  def set_validity_period(config, valid_from, validity, timezone \\ "Etc/UTC") do
    %CertProfile{
      config
      | valid_from: valid_from,
        validity: validity,
        validity_timezone: timezone
    }
  end

  def set_crl_dist_point(config, points) when is_list(points) do
    %{config | crl_dist_point: config.crl_dist_point ++ points}
  end

  def set_crl_dist_point(config, point) do
    %{config | crl_dist_point: [point | config.crl_dist_point]}
  end

  def set_ocsp_url(config, urls) when is_list(urls) do
    %{config | ocsp_url: config.ocsp_url ++ urls}
  end

  def set_ocsp_url(config, url) do
    %{config | ocsp_url: [url | config.ocsp_url]}
  end

  def set_issuer_url(config, urls) when is_list(urls) do
    %{config | issuer_url: config.issuer_url ++ urls}
  end

  def set_issuer_url(config, url) do
    %{config | issuer_url: [url | config.issuer_url]}
  end

  def set_timestamping_url(config, urls) when is_list(urls) do
    %{config | timestamping_url: config.timestamping_url ++ urls}
  end

  def set_timestamping_url(config, url) do
    %{config | timestamping_url: [url | config.timestamping_url]}
  end

  def set_ca_repository_url(config, urls) when is_list(urls) do
    %{config | ca_repository_url: config.ca_repository_url ++ urls}
  end

  def set_ca_repository_url(config, url) do
    %{config | ca_repository_url: [url | config.ca_repository_url]}
  end

  def verify_validity(%{valid_from: nil, cert_validity: %{not_before: nil}} = config) do
    Logger.debug("valid from is nil. set today date")

    CertProfile.verify_validity(%{
      config
      | valid_from: NaiveDateTime.to_erl(DateTime.now!(config.validity_timezone))
    })
  end

  def verify_validity(%{valid_from: :now, cert_validity: %{not_before: nil}} = config) do
    Logger.debug("valid from is nil. set today date")

    CertProfile.verify_validity(%{
      config
      | valid_from: NaiveDateTime.to_erl(DateTime.now!(config.validity_timezone))
    })
  end

  def verify_validity(
        %{valid_from: {_data, _time} = valid_from, cert_validity: %{not_before: nil}} =
          config
      ) do
    Logger.debug("valid from is #{inspect(valid_from)}. ")

    cvalid_from =
      DateTime.shift_zone!(
        DateTime.from_naive!(NaiveDateTime.from_erl!(valid_from), config.validity_timezone),
        "Etc/UTC"
      )

    CertProfile.verify_validity(%{
      config
      | cert_validity: %{config.cert_validity | not_before: cvalid_from}
    })
  end

  # valid_until
  def verify_validity(
        %{
          valid_from: {_d, _t},
          valid_until: nil,
          cert_validity: %{not_after: nil},
          validity: validity
        } = config
      )
      when is_list(validity) do
    Logger.debug("verify validity 1")

    Enum.reduce(validity, config, fn v, conf ->
      conf = %{conf | validity: v}
      verify_validity(conf)
    end)
  end

  def verify_validity(
        %{
          valid_from: {_d, _t} = vf,
          valid_until: vu,
          validity: {val, :year}
        } = config
      ) do
    Logger.debug("verify validity 2")
    # this structure allow chaining of validity
    case vu do
      nil ->
        vf = Timex.to_datetime(vf, config.validity_timezone)
        vfu = Timex.shift(vf, years: val)
        erldt = NaiveDateTime.to_erl(Timex.to_naive_datetime(vfu))
        Logger.debug("Shift #{val} Year: #{inspect(vf)} -> #{inspect(vfu)}")
        %{config | valid_until: erldt, cert_validity: %{config.cert_validity | not_after: vfu}}

      _ ->
        vf = Timex.to_datetime(vu, config.validity_timezone)
        vfu = Timex.shift(vf, years: val)
        erldt = NaiveDateTime.to_erl(Timex.to_naive_datetime(vfu))
        Logger.debug("Shift #{val} Year: #{inspect(vf)} -> #{inspect(vfu)}")
        %{config | valid_until: erldt, cert_validity: %{config.cert_validity | not_after: vfu}}
    end
  end

  def verify_validity(
        %{
          valid_from: {_d, _t} = vf,
          valid_until: vu,
          validity: {val, :month}
        } = config
      ) do
    Logger.debug("verify validity 3")
    # this structure allow chaining of validity
    case vu do
      nil ->
        vf = Timex.to_datetime(vf, config.validity_timezone)
        vfu = Timex.shift(vf, months: val)
        erldt = NaiveDateTime.to_erl(Timex.to_naive_datetime(vfu))
        Logger.debug("Shift #{val} Month: #{inspect(vf)} -> #{inspect(vfu)}")
        %{config | valid_until: erldt, cert_validity: %{config.cert_validity | not_after: vfu}}

      _ ->
        vf = Timex.to_datetime(vu, config.validity_timezone)
        vfu = Timex.shift(vf, months: val)
        erldt = NaiveDateTime.to_erl(Timex.to_naive_datetime(vfu))
        Logger.debug("Shift #{val} Month: #{inspect(vf)} -> #{inspect(vfu)}")
        %{config | valid_until: erldt, cert_validity: %{config.cert_validity | not_after: vfu}}
    end
  end

  def verify_validity(
        %{
          valid_from: {_d, _t} = vf,
          valid_until: vu,
          validity: {val, :day}
        } = config
      ) do
    Logger.debug("verify validity 4")
    # this structure allow chaining of validity
    case vu do
      nil ->
        vf = Timex.to_datetime(vf, config.validity_timezone)
        vfu = Timex.shift(vf, days: val)
        erldt = NaiveDateTime.to_erl(Timex.to_naive_datetime(vfu))
        Logger.debug("Shift #{val} Day: #{inspect(vf)} -> #{inspect(vfu)}")
        %{config | valid_until: erldt, cert_validity: %{config.cert_validity | not_after: vfu}}

      _ ->
        vf = Timex.to_datetime(vu, config.validity_timezone)
        vfu = Timex.shift(vf, days: val)
        erldt = NaiveDateTime.to_erl(Timex.to_naive_datetime(vfu))
        Logger.debug("Shift #{val} Day: #{inspect(vf)} -> #{inspect(vfu)}")
        %{config | valid_until: erldt, cert_validity: %{config.cert_validity | not_after: vfu}}
    end
  end

  def verify_validity(
        %{
          valid_from: {_d, _t} = vf,
          valid_until: vu,
          validity: {val, :hour}
        } = config
      ) do
    Logger.debug("verify validity 5")
    # this structure allow chaining of validity
    case vu do
      nil ->
        vf = Timex.to_datetime(vf, config.validity_timezone)
        vfu = Timex.shift(vf, hours: val)
        erldt = NaiveDateTime.to_erl(Timex.to_naive_datetime(vfu))
        Logger.debug("Shift #{val} Hour: #{inspect(vf)} -> #{inspect(vfu)}")
        %{config | valid_until: erldt, cert_validity: %{config.cert_validity | not_after: vfu}}

      _ ->
        vf = Timex.to_datetime(vu, config.validity_timezone)
        vfu = Timex.shift(vf, hours: val)
        erldt = NaiveDateTime.to_erl(Timex.to_naive_datetime(vfu))
        Logger.debug("Shift #{val} Hour: #{inspect(vf)} -> #{inspect(vfu)}")
        %{config | valid_until: erldt, cert_validity: %{config.cert_validity | not_after: vfu}}
    end
  end

  def verify_validity(
        %{
          valid_from: {_d, _t} = vf,
          valid_until: vu,
          validity: {val, :min}
        } = config
      ) do
    Logger.debug("verify validity 6")
    # this structure allow chaining of validity
    case vu do
      nil ->
        vf = Timex.to_datetime(vf, config.validity_timezone)
        vfu = Timex.shift(vf, minutes: val)
        erldt = NaiveDateTime.to_erl(Timex.to_naive_datetime(vfu))
        Logger.debug("Shift #{val} Minutes: #{inspect(vf)} -> #{inspect(vfu)}")
        %{config | valid_until: erldt, cert_validity: %{config.cert_validity | not_after: vfu}}

      _ ->
        vf = Timex.to_datetime(vu, config.validity_timezone)
        vfu = Timex.shift(vf, minutes: val)
        erldt = NaiveDateTime.to_erl(Timex.to_naive_datetime(vfu))
        Logger.debug("Shift #{val} Minutes: #{inspect(vf)} -> #{inspect(vfu)}")
        %{config | valid_until: erldt, cert_validity: %{config.cert_validity | not_after: vfu}}
    end
  end

  def verify_validity(
        %{
          valid_until: {_date, _time} = valid_until,
          cert_validity: %{not_after: nil}
        } = config
      ) do
    Logger.debug("verify validity 7")

    %{
      config
      | cert_validity: %{
          not_after:
            DateTime.from_naive(NaiveDateTime.from_erl!(valid_until), config.validity_timezone)
        }
    }
  end

  def verify_validity(%{valid_from: valid_from} = config) do
    Logger.debug("verify_validity error : #{inspect(config)}")
    {:error, {:invalid_valid_from_date_format, valid_from}}
  end

  def build_subject(%{name: nil} = _co),
    do: raise(SubjectMandatoryFieldMissing, message: "Name is mandatory")

  def build_subject(%{name: name} = _co) when is_binary(name) and byte_size(name) == 0,
    do: raise(SubjectMandatoryFieldMissing, message: "Name is mandatory")

  def build_subject(co) do
    res =
      Enum.reduce(Map.from_struct(co), [], fn {key, val}, acc ->
        Logger.debug("key : #{inspect(key)} / val : #{inspect(val)}")

        with true <- not is_nil(val) do
          case key do
            :name ->
              ["CN=#{val}" | acc]

            :serial ->
              ["serialNumber=#{val}" | acc]

            :org_unit ->
              with true <- is_list(val) do
                Enum.map(val, fn x -> "OU=#{x}" end) ++ acc
              else
                _ -> ["OU=#{val}" | acc]
              end

            :org ->
              ["O=#{val}" | acc]

            :state_locality ->
              ["ST=#{val}" | acc]

            :country ->
              ["C=#{val}" | acc]

            _ ->
              acc
          end
        else
          _ -> acc
        end
      end)

    "/" <> Enum.join(Enum.reverse(res), "/")
  end

  def set_issuer_key(ctx, isskey), do: %CertProfile{ctx | issuer_key: isskey}
  def get_issuer_key(ctx), do: ctx.issuer_key

  def set_issuer_cert(ctx, isscert), do: %CertProfile{ctx | issuer_cert: isscert}
  def get_issuer_cert(ctx), do: ctx.issuer_cert

  def set_cert_chain(ctx, chain) when is_list(chain),
    do: %CertProfile{ctx | cert_chain: ctx.cert_chain ++ chain}

  def set_cert_chain(ctx, chain) when not is_list(chain),
    do: %CertProfile{ctx | cert_chain: ctx.cert_chain ++ [chain]}

  def get_cert_chain(ctx), do: ctx.cert_chain

  def set_cert_digest(%CertProfile{} = prof, dgst), do: %CertProfile{prof | hash: dgst}
end

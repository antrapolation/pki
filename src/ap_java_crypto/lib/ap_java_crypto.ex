defmodule ApJavaCrypto do
  alias ExJrubyPort.JrubyService
  alias ExJrubyPort.JrubyJarContext

  use GenServer

  require Logger

  def start_link(params \\ %{}) do
    GenServer.start_link(__MODULE__, params,
      name: {:via, StrapProcReg, %{group: :ap_java_crypto, operation: :register}}
    )
  end

  def get_ap_java_crypto_service(),
    do:
      StrapProcReg.avail_services(%{
        group: :ap_java_crypto,
        service_selector: :random
      })

  def supported_pqc_signing_algo(opts \\ %{}) do
    GenServer.call(ApJavaCrypto.get_ap_java_crypto_service(), {:supported_pqc_signing_algo, opts})
  end

  def supported_pqc_kem_algo(opts \\ %{}) do
    GenServer.call(ApJavaCrypto.get_ap_java_crypto_service(), {:supported_pqc_kem_algo, opts})
  end

  def generate_keypair(algo, opts \\ %{}) do
    GenServer.call(ApJavaCrypto.get_ap_java_crypto_service(), {:gen_keypair, algo, opts})
  end

  def generate_csr(owner, privkey, opts \\ %{}) do
    GenServer.call(ApJavaCrypto.get_ap_java_crypto_service(), {:gen_csr, owner, privkey, opts})
  end

  def verify_csr(csr, opts \\ %{}) do
    GenServer.call(ApJavaCrypto.get_ap_java_crypto_service(), {:verify_csr, csr, opts})
  end

  def sign(data, privkey, opts \\ %{}) do
    GenServer.call(ApJavaCrypto.get_ap_java_crypto_service(), {:sign, data, privkey, opts})
  end

  def verify(data, signature, pubkey, opts \\ %{}) do
    GenServer.call(
      ApJavaCrypto.get_ap_java_crypto_service(),
      {:verify, data, signature, pubkey, opts}
    )
  end

  def issue_certificate(owner, profile, opts \\ %{})

  def issue_certificate({:der, _csr} = csr, profile, opts) do
    GenServer.call(
      ApJavaCrypto.get_ap_java_crypto_service(),
      {:issue_cert, csr, profile, opts}
    )
  end

  def issue_certificate(owner, _, _) when is_nil(owner) or not is_map(owner),
    do: {:error, {:owner_in_map_struct_is_expected, owner}}

  # name is required
  def issue_certificate(owner, _, _) when not is_map_key(owner, :name),
    do: {:error, :owner_public_key_is_required}

  def issue_certificate(%{name: name}, _, _) when is_nil(name) or bit_size(name) == 0,
    do: {:error, {:owner_name_in_string_is_required, name}}

  # public_key is required
  def issue_certificate(owner, _, _) when not is_map_key(owner, :public_key),
    do: {:error, :owner_public_key_is_required}

  def issue_certificate(%{public_key: pubkey}, _, _) when is_nil(pubkey),
    do: {:error, :owner_public_key_is_required}

  def issue_certificate(_, profile, _) when is_nil(profile) or not is_map(profile),
    do: {:error, {:cert_profile_in_map_struct_is_expected, profile}}

  # issuer_key is required
  def issue_certificate(_, profile, _) when not is_map_key(profile, :issuer_key),
    do: {:error, :issuer_key_is_required}

  def issue_certificate(_, %{issuer_key: isskey}, _) when is_nil(isskey),
    do: {:error, :issuer_key_is_required}

  def issue_certificate(_, %{self_sign: ssign, issue_cert: isscert}, _)
      when ssign and is_nil(isscert),
      do: {:error, :non_self_sign_requires_issuer_certificate_present}

  def issue_certificate(owner, profile, opts) do
    GenServer.call(
      ApJavaCrypto.get_ap_java_crypto_service(),
      {:issue_cert, owner, profile, opts}
    )
  end

  def x509_to_pem({:der, {:ap_java_crypto, cert}}) do
    {:pem,
     {:ap_java_crypto,
      "-----BEGIN CERTIFICATE-----\n#{Base.encode64(cert)}\n-----END CERTIFICATE-----\n"}}
  end

  def x509_to_der({:pem, {:ap_java_crypto, pem}}) do
    with {:ok, der} <-
           Base.decode64(
             String.replace(pem, "-----BEGIN CERTIFICATE-----\n", "")
             |> String.replace("\n-----END CERTIFICATE-----\n", "")
           ) do
      {:der, {:ap_java_crypto, der}}
    end
  end

  def encapsulate(pubkey, opts \\ %{}) do
    GenServer.call(ApJavaCrypto.get_ap_java_crypto_service(), {:encapsulate, pubkey, opts})
  end

  def decapsulate(cipher, privkey, opts \\ %{}) do
    GenServer.call(
      ApJavaCrypto.get_ap_java_crypto_service(),
      {:decapsulate, cipher, privkey, opts}
    )
  end

  def generate_p12(name, privkey, cert, chain, opts \\ %{}) do
    GenServer.call(
      ApJavaCrypto.get_ap_java_crypto_service(),
      {:generate_p12, name, privkey, cert, chain, opts}
    )
  end

  def load_p12(keystore, opts \\ %{}) do
    GenServer.call(
      ApJavaCrypto.get_ap_java_crypto_service(),
      {:load_p12, keystore, opts}
    )
  end

  def parse_cert(cert, opts \\ %{}) do
    GenServer.call(
      ApJavaCrypto.get_ap_java_crypto_service(),
      {:parse_cert, cert, opts}
    )
  end

  def verify_cert_validity(cert, ref \\ :now, opts \\ %{}) do
    GenServer.call(
      ApJavaCrypto.get_ap_java_crypto_service(),
      {:verify_cert_validity, cert, ref, opts}
    )
  end

  def cert_verify_issuer(subject, issuer, opts \\ %{}) do
    GenServer.call(
      ApJavaCrypto.get_ap_java_crypto_service(),
      {:cert_verify_issuer, subject, issuer, opts}
    )
  end

  # 
  # GenServer
  #
  def init(_args) do
    with {:ok, pid} <- ExJrubyPort.start_link(%JrubyJarContext{}),
         {:ok, spid} <-
           ExJrubyPort.start_node(pid, "#{__DIR__}/jruby/java_crypto.rb") do
      Process.flag(:trap_exit, true)
      Process.monitor(self())
      {:ok, %{node_pid: spid, jruby_port: pid}}
    else
      err -> {:abort, err}
    end
  end

  def handle_call({:supported_pqc_signing_algo, opts}, _from, state) do
    with {:ok, algos} <-
           JrubyService.call(state.node_pid, {:supported_pqc_signing_algo, opts}) do
      {:reply, {:ok, algos}, state}
    else
      err -> {:reply, err, state}
    end
  end

  def handle_call({:supported_pqc_kem_algo, opts}, _from, state) do
    with {:ok, _algos} = res <-
           JrubyService.call(state.node_pid, {:supported_pqc_kem_algo, opts}) do
      {:reply, res, state}
    else
      err -> {:reply, err, state}
    end
  end

  def handle_call({:gen_keypair, algo, opts}, _from, state) do
    case JrubyService.call(state.node_pid, {:generate_keypair, algo, opts}) do
      {:ok, algo, privKey, pubKey} ->
        {:reply, {:ok, {algo, :private_key, privKey}, {algo, :public_key, pubKey}}, state}

      {:ok, algo, privKey, pubKey, addres} ->
        {:reply, {:ok, {algo, :private_key, privKey}, {algo, :public_key, pubKey}, addres}, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call({:gen_csr, owner, privkey, opts}, _from, state) do
    case JrubyService.call(state.node_pid, {:generate_csr, owner, privkey, opts}) do
      {:ok, csr} ->
        {:reply, {:ok, {:der, csr}}, state}

      {:ok, csr, addres} ->
        {:reply, {:ok, {:der, csr}, addres}, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call({:verify_csr, {:der, csr}, opts}, _from, state) do
    case JrubyService.call(state.node_pid, {:verify_csr, csr, opts}) do
      res ->
        {:reply, res, state}
    end
  end

  def handle_call({:sign, data, {algo, :private_key, privkey}, opts}, _from, state) do
    case JrubyService.call(state.node_pid, {:sign, algo, data, privkey, opts}) do
      {:ok, sign} ->
        {:reply, {:ok, sign}, state}

      {:ok, sign, addres} ->
        {:reply, {:ok, sign, addres}, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call({:verify, data, signature, {algo, :public_key, pubkey}, opts}, _from, state) do
    case JrubyService.call(state.node_pid, {:verify, algo, data, signature, pubkey, opts}) do
      {:ok, true} ->
        {:reply, {:ok, true}, state}

      {:ok, true, addres} ->
        {:reply, {:ok, true, addres}, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call({:verify, data, signature, {:cert, cert}, opts}, _from, state) do
    with {:ok, cert_info} <- JrubyService.call(state.node_pid, {:parse_cert, cert, opts}) do
      algo =
        String.to_atom(String.downcase(String.replace(cert_info.public_key_algorithm, "-", "_")))

      case JrubyService.call(
             state.node_pid,
             {:verify, algo, data, signature, {:cert, cert}, opts}
           ) do
        {:ok, true} ->
          {:reply, {:ok, true}, state}

        {:ok, true, addres} ->
          {:reply, {:ok, true, addres}, state}

        other ->
          {:reply, other, state}
      end
    end
  end

  def handle_call(
        {:issue_cert, {:der, csr}, %{issuer_key: {iss_algo, :private_key, isskey}} = profile,
         opts},
        _from,
        state
      ) do
    case JrubyService.call(
           state.node_pid,
           {:issue_cert, iss_algo, csr, Map.put(profile, :issuer_key, isskey), opts}
         ) do
      {:ok, cert, _chain} ->
        {:reply, {:ok, {:der, cert}}, state}

      {:ok, cert, _chain, addres} ->
        {:reply, {:ok, {:der, cert}, addres}, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call(
        {:issue_cert, owner, %{issuer_key: {iss_algo, :private_key, isskey}} = profile, opts},
        _from,
        state
      ) do
    case JrubyService.call(
           state.node_pid,
           {:issue_cert, iss_algo, %{owner | public_key: translate_public_key(owner)},
            Map.put(profile, :issuer_key, isskey), opts}
         ) do
      {:ok, cert, _chain} ->
        {:reply, {:ok, {:der, cert}}, state}

      {:ok, cert, _chain, addres} ->
        {:reply, {:ok, {:der, cert}, addres}, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call({:encapsulate, {algo, :public_key, pubkey}, opts}, _from, state) do
    case JrubyService.call(state.node_pid, {:encapsulate, algo, pubkey, opts}) do
      {:ok, _secret, _cipher} = res ->
        {:reply, res, state}

      {:ok, _secret, _cipher, _addres} = res ->
        {:reply, res, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call({:decapsulate, cipher, {algo, :private_key, privkey}, opts}, _from, state) do
    case JrubyService.call(state.node_pid, {:decapsulate, algo, cipher, privkey, opts}) do
      {:ok, _secret} = res ->
        {:reply, res, state}

      {:ok, _secret, _addres} = res ->
        {:reply, res, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call({:generate_p12, name, privkey, cert, chain, opts}, _from, state) do
    {:der, ucert} = cert

    uchain =
      Enum.map(chain, fn c ->
        {:der, cc} = c
        cc
      end)

    Logger.debug("ucert : #{inspect(ucert)}")
    Logger.debug("uchain : #{inspect(uchain)}")

    case JrubyService.call(
           state.node_pid,
           {:generate_pkcs12, name, privkey, [ucert] ++ uchain, opts}
         ) do
      {:ok, _p12} = res ->
        {:reply, res, state}

      {:ok, _p12, _addres} = res ->
        {:reply, res, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call({:load_p12, keystore, opts}, _from, state) do
    case JrubyService.call(state.node_pid, {:load_pkcs12, keystore, opts}) do
      {:ok, _content} = res ->
        {:reply, res, state}

      {:ok, _content, _addres} = res ->
        {:reply, res, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call({:parse_cert, cert, opts}, _from, state) do
    case JrubyService.call(state.node_pid, {:parse_cert, cert, opts}) do
      {:ok, _cert_info} = res ->
        {:reply, res, state}

      {:ok, _cert_info, _addres} = res ->
        {:reply, res, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call({:verify_cert_validity, {:der, cert}, ref, opts}, _from, state) do
    case JrubyService.call(state.node_pid, {:verify_cert_validity, cert, ref, opts}) do
      {:ok, true} = res ->
        {:reply, res, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call({:cert_verify_issuer, {:der, subject}, {:der, issuer}, opts}, _from, state) do
    case JrubyService.call(state.node_pid, {:cert_verify_issuer, subject, issuer, opts}) do
      {:ok, true} = res ->
        {:reply, res, state}

      other ->
        {:reply, other, state}
    end
  end

  def terminate(reason, _state) do
    Logger.debug("ApJavaCrypto terminating... #{inspect(reason)}")
    :ok
  end

  defp translate_public_key(%{public_key: {_pubalgo, :public_key, _owner_pubkey} = pubkey}),
    do: pubkey

  defp translate_public_key(%{public_key: %{variant: var, value: owner_pubkey}}),
    do: {var, :public_key, owner_pubkey}
end

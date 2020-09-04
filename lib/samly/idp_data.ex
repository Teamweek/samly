defmodule Samly.IdpData do
  @moduledoc false

  require Logger
  require Samly.Esaml
  alias Samly.{Esaml, Helper, IdpData, SpData, XmlAdapter}

  @type nameid_format :: :unknown | charlist()
  @type certs :: [binary()]
  @type url :: nil | binary()

  defstruct id: "",
            sp_id: "",
            base_url: nil,
            metadata_file: nil,
            pre_session_create_pipeline: nil,
            use_redirect_for_req: false,
            sign_requests: true,
            sign_metadata: true,
            signed_assertion_in_resp: true,
            signed_envelopes_in_resp: true,
            allow_idp_initiated_flow: false,
            allowed_target_urls: [],
            entity_id: "",
            signed_requests: "",
            certs: [],
            sso_redirect_url: nil,
            sso_post_url: nil,
            slo_redirect_url: nil,
            slo_post_url: nil,
            nameid_format: :unknown,
            fingerprints: [],
            esaml_idp_rec: Esaml.esaml_idp_metadata(),
            esaml_sp_rec: Esaml.esaml_sp(),
            valid?: false

  @type t :: %__MODULE__{
          id: binary(),
          sp_id: binary(),
          base_url: nil | binary(),
          metadata_file: nil | binary() | map(),
          pre_session_create_pipeline: nil | module(),
          use_redirect_for_req: boolean(),
          sign_requests: boolean(),
          sign_metadata: boolean(),
          signed_assertion_in_resp: boolean(),
          signed_envelopes_in_resp: boolean(),
          allow_idp_initiated_flow: boolean(),
          allowed_target_urls: nil | [binary()],
          entity_id: binary(),
          signed_requests: binary(),
          certs: certs(),
          sso_redirect_url: url(),
          sso_post_url: url(),
          slo_redirect_url: url(),
          slo_post_url: url(),
          nameid_format: nameid_format(),
          fingerprints: [binary()],
          esaml_idp_rec: :esaml_idp_metadata,
          esaml_sp_rec: :esaml_sp,
          valid?: boolean()
        }

  @type id :: binary()

  def store() do
    Application.get_env(:samly, Samly.Provider, [])
    |> Keyword.get(:idp_data_store, Samly.IdpDataStore.Config)
  end

  @spec load_providers([map], %{required(id()) => %SpData{}}) ::
          %{required(id()) => %IdpData{}} | no_return()
  def load_providers(prov_config, service_providers) do
    prov_config
    |> Enum.map(fn idp_config -> load_provider(idp_config, service_providers) end)
    |> Enum.filter(fn idp_data -> idp_data.valid? end)
    |> Enum.map(fn idp_data -> {idp_data.id, idp_data} end)
    |> Enum.into(%{})
  end

  @spec load_provider(map(), %{required(id()) => %SpData{}}) :: %IdpData{} | no_return
  def load_provider(idp_config, service_providers) do
    %IdpData{}
    |> save_idp_config(idp_config)
    |> load_metadata(idp_config)
    |> override_nameid_format(idp_config)
    |> update_esaml_recs(service_providers, idp_config)
    |> verify_slo_url()
  end

  @spec save_idp_config(%IdpData{}, map()) :: %IdpData{}
  defp save_idp_config(idp_data, %{id: id, sp_id: sp_id} = opts_map)
       when is_binary(id) and is_binary(sp_id) do
    %IdpData{idp_data | id: id, sp_id: sp_id, base_url: Map.get(opts_map, :base_url)}
    |> set_metadata_file(opts_map)
    |> set_pipeline(opts_map)
    |> set_allowed_target_urls(opts_map)
    |> set_boolean_attr(opts_map, :use_redirect_for_req)
    |> set_boolean_attr(opts_map, :sign_requests)
    |> set_boolean_attr(opts_map, :sign_metadata)
    |> set_boolean_attr(opts_map, :signed_assertion_in_resp)
    |> set_boolean_attr(opts_map, :signed_envelopes_in_resp)
    |> set_boolean_attr(opts_map, :allow_idp_initiated_flow)
  end

  @spec load_metadata(%IdpData{}, map()) :: %IdpData{}
  defp load_metadata(%IdpData{metadata_file: metadata_file} = idp_data, _opts_map)
       when is_binary(metadata_file) do
    with {:reading, {:ok, raw_xml}} <- {:reading, File.read(metadata_file)},
         {:parsing, {:ok, idp_data}} <- {:parsing, from_xml(raw_xml, idp_data)} do
      idp_data
    else
      {:reading, {:error, reason}} ->
        Logger.error(
          "[Samly] Failed to read metadata_file [#{inspect(metadata_file)}]: #{inspect(reason)}"
        )

        idp_data

      {:parsing, {:error, reason}} ->
        Logger.error(
          "[Samly] Invalid metadata_file content [#{inspect(metadata_file)}]: #{inspect(reason)}"
        )

        idp_data
    end
  end

  defp load_metadata(%IdpData{metadata_file: data} = idp_data, _opts_map) when is_map(data) do
    # TODO defstruct on the map:
    # %{
    #  certs: ["xyz"],
    #  entity_id: "http://www.abc.com/def",
    #  nameid_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddressurn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    #  signed_requests: "false",
    #  slo_post_url: nil,
    #  slo_redirect_url: nil,
    #  sso_post_url: "https://url.com/sso/saml",
    #  sso_redirect_url: "https://url.com/sso/saml"
    # }

    %IdpData{
      idp_data
      | entity_id: data.entity_id,
        signed_requests: data.signed_requests,
        certs: data.certs,
        fingerprints: idp_cert_fingerprints(data.certs),
        sso_redirect_url: data.sso_redirect_url,
        sso_post_url: data.sso_post_url,
        slo_redirect_url: data.slo_redirect_url,
        slo_post_url: data.slo_post_url,
        nameid_format: data.nameid_format
    }
  end

  @spec update_esaml_recs(%IdpData{}, %{required(id()) => %SpData{}}, map()) :: %IdpData{}
  defp update_esaml_recs(idp_data, service_providers, opts_map) do
    case Map.get(service_providers, idp_data.sp_id) do
      %SpData{} = sp ->
        idp_data = %IdpData{idp_data | esaml_idp_rec: to_esaml_idp_metadata(idp_data, opts_map)}
        idp_data = %IdpData{idp_data | esaml_sp_rec: get_esaml_sp(sp, idp_data)}
        %IdpData{idp_data | valid?: cert_config_ok?(idp_data, sp)}

      _ ->
        Logger.error("[Samly] Unknown/invalid sp_id: #{idp_data.sp_id}")
        idp_data
    end
  end

  @spec cert_config_ok?(%IdpData{}, %SpData{}) :: boolean
  defp cert_config_ok?(%IdpData{} = idp_data, %SpData{} = sp_data) do
    if (idp_data.sign_metadata || idp_data.sign_requests) &&
         (sp_data.cert == :undefined || sp_data.key == :undefined) do
      Logger.error("[Samly] SP cert or key missing - Skipping identity provider: #{idp_data.id}")
      false
    else
      true
    end
  end

  @spec verify_slo_url(%IdpData{}) :: %IdpData{}
  defp verify_slo_url(%IdpData{} = idp_data) do
    if idp_data.valid? && idp_data.slo_redirect_url == nil && idp_data.slo_post_url == nil do
      Logger.warn("[Samly] SLO Endpoint missing in [#{inspect(idp_data.metadata_file)}]")
    end

    idp_data
  end

  @default_metadata_file "idp_metadata.xml"

  @spec set_metadata_file(%IdpData{}, map()) :: %IdpData{}
  defp set_metadata_file(%IdpData{} = idp_data, %{} = opts_map) do
    %IdpData{idp_data | metadata_file: Map.get(opts_map, :metadata_file, @default_metadata_file)}
  end

  @spec set_pipeline(%IdpData{}, map()) :: %IdpData{}
  defp set_pipeline(%IdpData{} = idp_data, %{} = opts_map) do
    pipeline = Map.get(opts_map, :pre_session_create_pipeline)
    %IdpData{idp_data | pre_session_create_pipeline: pipeline}
  end

  defp set_allowed_target_urls(%IdpData{} = idp_data, %{} = opts_map) do
    target_urls =
      case Map.get(opts_map, :allowed_target_urls, nil) do
        nil -> nil
        urls when is_list(urls) -> Enum.filter(urls, &is_binary/1)
      end

    %IdpData{idp_data | allowed_target_urls: target_urls}
  end

  @spec override_nameid_format(%IdpData{}, map()) :: %IdpData{}
  defp override_nameid_format(%IdpData{} = idp_data, idp_config) do
    nameid_format =
      case Map.get(idp_config, :nameid_format, "") do
        "" ->
          idp_data.nameid_format

        format when is_binary(format) ->
          to_charlist(format)

        :email ->
          'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'

        :x509 ->
          'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName'

        :windows ->
          'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName'

        :krb ->
          'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos'

        :persistent ->
          'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'

        :transient ->
          'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'

        invalid_nameid_format ->
          Logger.error(
            "[Samly] invalid nameid_format [#{inspect(idp_data.metadata_file)}]: #{
              inspect(invalid_nameid_format)
            }"
          )

          idp_data.nameid_format
      end

    %IdpData{idp_data | nameid_format: nameid_format}
  end

  @spec set_boolean_attr(%IdpData{}, map(), atom()) :: %IdpData{}
  defp set_boolean_attr(%IdpData{} = idp_data, %{} = opts_map, attr_name)
       when is_atom(attr_name) do
    v = Map.get(opts_map, attr_name)
    if is_boolean(v), do: Map.put(idp_data, attr_name, v), else: idp_data
  end

  @spec from_xml(binary, %IdpData{}) :: {:ok, %IdpData{}}
  def from_xml(metadata_xml, idp_data) when is_binary(metadata_xml) do
    {:ok, data} = XmlAdapter.import(metadata_xml)

    {:ok,
     %IdpData{
       idp_data
       | entity_id: data.entity_id,
         signed_requests: data.signed_requests,
         certs: data.certs,
         fingerprints: idp_cert_fingerprints(data.certs),
         sso_redirect_url: data.sso_redirect_url,
         sso_post_url: data.sso_post_url,
         slo_redirect_url: data.slo_redirect_url,
         slo_post_url: data.slo_post_url,
         nameid_format: data.nameid_format
     }}
  end

  # @spec to_esaml_idp_metadata(IdpData.t(), map()) :: :esaml_idp_metadata
  defp to_esaml_idp_metadata(%IdpData{} = idp_data, %{} = idp_config) do
    {sso_url, slo_url} = get_sso_slo_urls(idp_data, idp_config)
    sso_url = if sso_url, do: String.to_charlist(sso_url), else: []
    slo_url = if slo_url, do: String.to_charlist(slo_url), else: :undefined

    Esaml.esaml_idp_metadata(
      entity_id: String.to_charlist(idp_data.entity_id),
      login_location: sso_url,
      logout_location: slo_url,
      name_format: idp_data.nameid_format
    )
  end

  defp get_sso_slo_urls(%IdpData{} = idp_data, %{use_redirect_for_req: true}) do
    {idp_data.sso_redirect_url, idp_data.slo_redirect_url}
  end

  defp get_sso_slo_urls(%IdpData{} = idp_data, %{use_redirect_for_req: false}) do
    {idp_data.sso_post_url, idp_data.slo_post_url}
  end

  defp get_sso_slo_urls(%IdpData{} = idp_data, _opts_map) do
    {
      idp_data.sso_post_url || idp_data.sso_redirect_url,
      idp_data.slo_post_url || idp_data.slo_redirect_url
    }
  end

  @spec idp_cert_fingerprints(certs()) :: [binary()]
  defp idp_cert_fingerprints(certs) when is_list(certs) do
    certs
    |> Enum.map(&Base.decode64!/1)
    |> Enum.map(&cert_fingerprint/1)
    |> Enum.map(&String.to_charlist/1)
    |> :esaml_util.convert_fingerprints()
  end

  defp cert_fingerprint(dercert) do
    "sha256:" <> (:sha256 |> :crypto.hash(dercert) |> Base.encode64())
  end

  # @spec get_esaml_sp(%SpData{}, %IdpData{}) :: :esaml_sp
  defp get_esaml_sp(%SpData{} = sp_data, %IdpData{} = idp_data) do
    idp_id_from = Application.get_env(:samly, :idp_id_from)
    path_segment_idp_id = if idp_id_from == :subdomain, do: nil, else: idp_data.id

    sp_entity_id =
      case sp_data.entity_id do
        "" -> :undefined
        id -> String.to_charlist(id)
      end

    Esaml.esaml_sp(
      org:
        Esaml.esaml_org(
          name: String.to_charlist(sp_data.org_name),
          displayname: String.to_charlist(sp_data.org_displayname),
          url: String.to_charlist(sp_data.org_url)
        ),
      tech:
        Esaml.esaml_contact(
          name: String.to_charlist(sp_data.contact_name),
          email: String.to_charlist(sp_data.contact_email)
        ),
      key: sp_data.key,
      certificate: sp_data.cert,
      sp_sign_requests: idp_data.sign_requests,
      sp_sign_metadata: idp_data.sign_metadata,
      idp_signs_envelopes: idp_data.signed_envelopes_in_resp,
      idp_signs_assertions: idp_data.signed_assertion_in_resp,
      trusted_fingerprints: idp_data.fingerprints,
      metadata_uri: Helper.get_metadata_uri(idp_data.base_url, path_segment_idp_id),
      consume_uri: Helper.get_consume_uri(idp_data.base_url, path_segment_idp_id),
      logout_uri: Helper.get_logout_uri(idp_data.base_url, path_segment_idp_id),
      entity_id: sp_entity_id
    )
  end
end

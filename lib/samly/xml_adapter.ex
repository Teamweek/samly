defmodule Samly.XmlAdapter do
  import SweetXml

  @type nameid_format :: :unknown | charlist()
  @type certs :: [binary()]
  @type url :: nil | binary()

  @entdesc "md:EntityDescriptor"
  @idpdesc "md:IDPSSODescriptor"
  @signedreq "WantAuthnRequestsSigned"
  @nameid "md:NameIDFormat"
  @keydesc "md:KeyDescriptor"
  @ssos "md:SingleSignOnService"
  @slos "md:SingleLogoutService"
  @redirect "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
  @post "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

  @entity_id_selector ~x"//#{@entdesc}/@entityID"sl
  @nameid_format_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@nameid}/text()"s
  @req_signed_selector ~x"//#{@entdesc}/#{@idpdesc}/@#{@signedreq}"s
  @sso_redirect_url_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@ssos}[@Binding = '#{@redirect}']/@Location"s
  @sso_post_url_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@ssos}[@Binding = '#{@post}']/@Location"s
  @slo_redirect_url_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@slos}[@Binding = '#{@redirect}']/@Location"s
  @slo_post_url_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@slos}[@Binding = '#{@post}']/@Location"s
  @signing_keys_selector ~x"//#{@entdesc}/#{@idpdesc}/#{@keydesc}[@use != 'encryption']"l
  @cert_selector ~x"./ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()"s

  def import(metadata_xml) when is_binary(metadata_xml) do
    xml_opts = [
      space: :normalize,
      namespace_conformant: true,
      comments: false,
      default_attrs: true
    ]

    md_xml = SweetXml.parse(metadata_xml, xml_opts)
    signing_certs = get_signing_certs(md_xml)

    {:ok,
     %{
       entity_id: get_entity_id(md_xml),
       signed_requests: get_req_signed(md_xml),
       certs: signing_certs,
       sso_redirect_url: get_sso_redirect_url(md_xml),
       sso_post_url: get_sso_post_url(md_xml),
       slo_redirect_url: get_slo_redirect_url(md_xml),
       slo_post_url: get_slo_post_url(md_xml),
       nameid_format: get_nameid_format(md_xml)
     }}
  end

  @spec get_nameid_format(:xmlElement) :: nameid_format()
  defp get_nameid_format(md_elem) do
    case get_data(md_elem, @nameid_format_selector) do
      "" -> :unknown
      nameid_format -> to_charlist(nameid_format)
    end
  end

  @spec get_signing_certs(:xmlElement) :: certs()
  defp get_signing_certs(md_elem), do: get_certs(md_elem, @signing_keys_selector)

  @spec get_certs(:xmlElement, %SweetXpath{}) :: certs()
  defp get_certs(md_elem, key_selector) do
    md_elem
    |> xpath(key_selector |> add_ns())
    |> Enum.map(fn e ->
      # Extract base64 encoded cert from XML (strip away any whitespace)
      cert = xpath(e, @cert_selector |> add_ns())

      cert
      |> String.split()
      |> Enum.map(&String.trim/1)
      |> Enum.join()
    end)
  end

  @spec get_entity_id(:xmlElement) :: binary()
  defp get_entity_id(md_elem) do
    md_elem |> xpath(@entity_id_selector |> add_ns()) |> hd() |> String.trim()
  end

  @spec get_req_signed(:xmlElement) :: binary()
  defp get_req_signed(md_elem), do: get_data(md_elem, @req_signed_selector)

  @spec get_sso_redirect_url(:xmlElement) :: url()
  defp get_sso_redirect_url(md_elem), do: get_url(md_elem, @sso_redirect_url_selector)

  @spec get_sso_post_url(:xmlElement) :: url()
  defp get_sso_post_url(md_elem), do: get_url(md_elem, @sso_post_url_selector)

  @spec get_slo_redirect_url(:xmlElement) :: url()
  defp get_slo_redirect_url(md_elem), do: get_url(md_elem, @slo_redirect_url_selector)

  @spec get_slo_post_url(:xmlElement) :: url()
  defp get_slo_post_url(md_elem), do: get_url(md_elem, @slo_post_url_selector)

  @spec get_url(:xmlElement, %SweetXpath{}) :: url()
  defp get_url(md_elem, selector) do
    case get_data(md_elem, selector) do
      "" -> nil
      url -> url
    end
  end

  @spec get_data(:xmlElement, %SweetXpath{}) :: binary()
  defp get_data(md_elem, selector) do
    md_elem |> xpath(selector |> add_ns()) |> String.trim()
  end

  @spec add_ns(%SweetXpath{}) :: %SweetXpath{}
  defp add_ns(xpath) do
    xpath
    |> SweetXml.add_namespace("md", "urn:oasis:names:tc:SAML:2.0:metadata")
    |> SweetXml.add_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
  end
end

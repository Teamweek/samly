defmodule XmlAdapterTest do
  use ExUnit.Case
  alias Samly.XmlAdapter

  test "valid parsed fields" do
    file = "test/data/shibboleth_idp_metadata.xml"
    expected = expected()

    assert {:reading, {:ok, raw_xml}} = {:reading, File.read(file)}
    assert {:ok, ^expected} = XmlAdapter.import(raw_xml)
  end

  defp expected() do
    %{
      certs: [
        "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"
      ],
      entity_id: "https://samly.idp:4443/idp/shibboleth",
      nameid_format: :unknown,
      signed_requests: "",
      slo_post_url: "https://samly.idp:4443/idp/profile/SAML2/POST/SLO",
      slo_redirect_url: "https://samly.idp:4443/idp/profile/SAML2/Redirect/SLO",
      sso_post_url: "https://samly.idp:4443/idp/profile/SAML2/POST/SSO",
      sso_redirect_url: "https://samly.idp:4443/idp/profile/SAML2/Redirect/SSO"
    }
  end
end

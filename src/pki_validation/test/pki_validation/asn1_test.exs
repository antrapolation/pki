defmodule PkiValidation.Asn1Test do
  use ExUnit.Case, async: true

  alias PkiValidation.Asn1

  test "encode and decode an OCSPResponseStatus successful" do
    {:ok, der} = Asn1.encode(:OCSPResponseStatus, :successful)
    assert is_binary(der)
    assert {:ok, :successful} = Asn1.decode(:OCSPResponseStatus, der)
  end
end

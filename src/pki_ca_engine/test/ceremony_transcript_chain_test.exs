defmodule PkiCaEngine.CeremonyTranscriptChainTest do
  use ExUnit.Case, async: true

  alias PkiMnesia.Structs.CeremonyTranscript

  defp make_event(n) do
    %{
      "timestamp" => "2024-01-0#{n}T00:00:00Z",
      "actor" => "officer_#{n}",
      "action" => "step_#{n}",
      "details" => %{"seq" => n}
    }
  end

  defp build_transcript(count) do
    transcript = CeremonyTranscript.new(%{ceremony_id: "test-ceremony-1"})

    Enum.reduce(1..count, transcript, fn n, acc ->
      CeremonyTranscript.append(acc, make_event(n))
    end)
  end

  describe "CeremonyTranscript hash chain" do
    test "5 appended entries produce a valid chain" do
      transcript = build_transcript(5)

      assert length(transcript.entries) == 5
      assert CeremonyTranscript.verify_chain(transcript) == :ok
    end

    test "tampering entry 3 breaks the chain at index 3" do
      transcript = build_transcript(5)

      # Tamper with entry 3's "action" field (0-based index 2)
      tampered_entries =
        List.update_at(transcript.entries, 2, fn entry ->
          Map.put(entry, "action", "TAMPERED")
        end)

      tampered = %{transcript | entries: tampered_entries}

      assert CeremonyTranscript.verify_chain(tampered) == {:error, {:broken_at, 3}}
    end
  end
end

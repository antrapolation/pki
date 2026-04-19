defmodule PkiReplica do
  @moduledoc """
  Replica supervisor application for multi-host Mnesia replication.

  Runs on the replica server and provides:
  - ClusterMonitor: heartbeat monitoring of the primary platform node
  - FailoverManager: alert + manual promotion orchestration
  - PortAllocator: in-memory port pool for post-promotion HTTP endpoints
  """
end

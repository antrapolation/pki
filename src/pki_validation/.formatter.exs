# Used by "mix format"
[
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"],
  import_deps: [:ecto, :ecto_sql, :plug],
  locals_without_parens: [
    # Ecto.Schema
    field: 1,
    field: 2,
    field: 3,
    belongs_to: 2,
    belongs_to: 3,
    has_one: 2,
    has_one: 3,
    has_many: 2,
    has_many: 3,
    many_to_many: 2,
    many_to_many: 3,
    embeds_one: 2,
    embeds_one: 3,
    embeds_many: 2,
    embeds_many: 3,
    timestamps: 0,
    timestamps: 1,
    # Plug.Builder / Plug.Router
    plug: 1,
    plug: 2,
    get: 2,
    get: 3,
    post: 2,
    post: 3,
    put: 2,
    put: 3,
    delete: 2,
    delete: 3,
    match: 2,
    match: 3,
    forward: 2,
    forward: 3
  ]
]

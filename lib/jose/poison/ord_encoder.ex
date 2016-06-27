if Code.ensure_loaded?(Poison) do
  defmodule JOSE.Poison.Encode do
    defmacro __using__(_) do
      quote do
        defp encode_name(value) do
          cond do
            is_binary(value) ->
              value
            is_atom(value) ->
              Atom.to_string(value)
            true ->
              raise Poison.EncodeError, value: value,
                message: "expected string or atom key, got: #{inspect value}"
          end
        end
      end
    end
  end

  defprotocol JOSE.Poison.OrdEncoder do
    @fallback_to_any true

    def encode(value, options)
  end

  defimpl JOSE.Poison.OrdEncoder, for: Atom do
    def encode(atom, options), do: Poison.Encoder.Atom.encode(atom, options)
  end

  defimpl JOSE.Poison.OrdEncoder, for: BitString do
    def encode(string, options), do: Poison.Encoder.BitString.encode(string, options)
  end

  defimpl JOSE.Poison.OrdEncoder, for: Integer do
    def encode(integer, options), do: Poison.Encoder.Integer.encode(integer, options)
  end

  defimpl JOSE.Poison.OrdEncoder, for: Float do
    def encode(float, options), do: Poison.Encoder.Float.encode(float, options)
  end

  defimpl JOSE.Poison.OrdEncoder, for: Map do
    alias JOSE.Poison.OrdEncoder

    @compile :inline_list_funcs

    use JOSE.Poison.Encode

    def encode(map, _) when map_size(map) < 1, do: "{}"

    def encode(map, options) do
      encode(map, false, options)
    end

    def encode(map, _, options) do
      fun = &[?,, OrdEncoder.BitString.encode(encode_name(&1), options), ?:,
                  OrdEncoder.encode(:maps.get(&1, map), options) | &2]
      [?{, tl(:lists.foldr(fun, [], :maps.keys(map))), ?}]
    end
  end

  defimpl JOSE.Poison.OrdEncoder, for: List do
    alias JOSE.Poison.OrdEncoder

    @compile :inline_list_funcs

    def encode([], _), do: "[]"

    def encode(list, options) do
      encode(list, false, options)
    end

    def encode(list, false, options) do
      fun = &[?,, OrdEncoder.encode(&1, options) | &2]
      [?[, tl(:lists.foldr(fun, [], list)), ?]]
    end
  end

  defimpl JOSE.Poison.OrdEncoder, for: [Range, Stream, HashSet] do

    def encode(collection, options) do
      encode(collection, false, options)
    end

    def encode(collection, false, options) do
      fun = &[?,, JOSE.Poison.OrdEncoder.encode(&1, options)]

      case Enum.flat_map(collection, fun) do
        [] -> "[]"
        [_ | tail] -> [?[, tail, ?]]
      end
    end
  end

  defimpl JOSE.Poison.OrdEncoder, for: HashDict do
    alias JOSE.Poison.OrdEncoder

    use JOSE.Poison.Encode

    def encode(dict, options) do
      if HashDict.size(dict) < 1 do
        "{}"
      else
        encode(dict, false, options)
      end
    end

    def encode(dict, false, options) do
      fun = fn {key, value} ->
        [?,, OrdEncoder.BitString.encode(encode_name(key), options), ?:,
             OrdEncoder.encode(value, options)]
      end

      [?{, tl(Enum.flat_map(dict, fun)), ?}]
    end
  end

  defimpl JOSE.Poison.OrdEncoder, for: Any do
    def encode(%{__struct__: _} = struct, options) do
      JOSE.Poison.OrdEncoder.Map.encode(Map.from_struct(struct), options)
    end

    def encode(value, _options) do
      raise Poison.EncodeError, value: value
    end
  end
end

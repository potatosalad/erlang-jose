defmodule JOSE.Poison.LexicalEncodeError do
  defexception value: nil, message: nil

  def message(%{value: value, message: nil}) do
    "unable to encode value: #{inspect value}"
  end

  def message(%{message: message}) do
    message
  end
end

defmodule JOSE.Poison.LexicalEncode do
  defmacro __using__(_) do
    quote do
      @compile {:inline, encode_name: 1}

      # Fast path encoding string keys
      defp encode_name(value) when is_binary(value) do
        value
      end

      defp encode_name(value) do
        case String.Chars.impl_for(value) do
          nil ->
            module =
              if Code.ensure_loaded?(Poison) do
                Poison.EncodeError
              else
                JOSE.Poison.LexicalEncodeError
              end
            raise module, value: value,
              message: "expected a String.Chars encodable value, got: #{inspect value}"
          impl ->
            impl.to_string(value)
        end
      end
    end
  end
end

defmodule JOSE.Poison.LexicalPretty do
  defmacro __using__(_) do
    quote do
      @default_indent 2
      @default_offset 0

      @compile {:inline, pretty: 1, indent: 1, offset: 1, offset: 2, spaces: 1}

      defp pretty(options) do
        !!Keyword.get(options, :pretty)
      end

      defp indent(options) do
        Keyword.get(options, :indent, @default_indent)
      end

      defp offset(options) do
        Keyword.get(options, :offset, @default_offset)
      end

      defp offset(options, value) do
        Keyword.put(options, :offset, value)
      end

      defp spaces(count) do
        :binary.copy(" ", count)
      end
    end
  end
end

defprotocol JOSE.Poison.LexicalEncoder do
  @fallback_to_any true

  def encode(value, options)
end

defimpl JOSE.Poison.LexicalEncoder, for: Atom do
  def encode(atom, options) do
    apply(Poison.Encoder.Atom, :encode, [atom, options])
  end
end

defimpl JOSE.Poison.LexicalEncoder, for: BitString do
  def encode(string, options) do
    apply(Poison.Encoder.BitString, :encode, [string, options])
  end
end

defimpl JOSE.Poison.LexicalEncoder, for: Integer do
  def encode(integer, options) do
    apply(Poison.Encoder.Integer, :encode, [integer, options])
  end
end

defimpl JOSE.Poison.LexicalEncoder, for: Float do
  def encode(float, options) do
    apply(Poison.Encoder.Float, :encode, [float, options])
  end
end

defimpl JOSE.Poison.LexicalEncoder, for: Map do
  alias JOSE.Poison.LexicalEncoder

  @compile :inline_list_funcs

  use JOSE.Poison.LexicalPretty
  use JOSE.Poison.LexicalEncode

  # TODO: Remove once we require Elixir 1.1+
  defmacro __deriving__(module, struct, options) do
    JOSE.Poison.LexicalEncoder.Any.deriving(module, struct, options)
  end

  def encode(map, _) when map_size(map) < 1, do: "{}"

  def encode(map, options) do
    map
    |> strict_keys(Keyword.get(options, :strict_keys, false))
    |> encode(pretty(options), options)
  end

  def encode(map, true, options) do
    indent = indent(options)
    offset = offset(options) + indent
    options = offset(options, offset)

    fun = &[",\n", spaces(offset), LexicalEncoder.BitString.encode(encode_name(&1), options), ": ",
                                   LexicalEncoder.encode(:maps.get(&1, map), options) | &2]
    ["{\n", tl(:lists.foldr(fun, [], :maps.keys(map))), ?\n, spaces(offset - indent), ?}]
  end

  def encode(map, _, options) do
    fun = &[?,, LexicalEncoder.BitString.encode(encode_name(&1), options), ?:,
                LexicalEncoder.encode(:maps.get(&1, map), options) | &2]
    [?{, tl(:lists.foldr(fun, [], :maps.keys(map))), ?}]
  end

  defp strict_keys(map, false), do: map
  defp strict_keys(map, true) do
    Enum.each(map, fn {key, _value} ->
      name = encode_name(key)
      if Map.has_key?(map, name) do
        module =
          if Code.ensure_loaded?(Poison) do
            Poison.EncodeError
          else
            JOSE.Poison.LexicalEncodeError
          end
        raise module, value: name,
          message: "duplicate key found: #{inspect key}"
      end
    end)
    map
  end
end

defimpl JOSE.Poison.LexicalEncoder, for: List do
  alias JOSE.Poison.LexicalEncoder

  use JOSE.Poison.LexicalPretty

  @compile :inline_list_funcs

  def encode([], _), do: "[]"

  def encode(list, options) do
    encode(list, pretty(options), options)
  end

  def encode(list, false, options) do
    fun = &[?,, LexicalEncoder.encode(&1, options) | &2]
    [?[, tl(:lists.foldr(fun, [], list)), ?]]
  end

  def encode(list, true, options) do
    indent = indent(options)
    offset = offset(options) + indent
    options = offset(options, offset)

    fun = &[",\n", spaces(offset), LexicalEncoder.encode(&1, options) | &2]
    ["[\n", tl(:lists.foldr(fun, [], list)), ?\n, spaces(offset - indent), ?]]
  end
end

defimpl JOSE.Poison.LexicalEncoder, for: [Range, Stream, MapSet, HashSet] do
  use JOSE.Poison.LexicalPretty

  def encode(collection, options) do
    encode(collection, pretty(options), options)
  end

  def encode(collection, false, options) do
    fun = &[?,, JOSE.Poison.LexicalEncoder.encode(&1, options)]

    case Enum.flat_map(collection, fun) do
      [] -> "[]"
      [_ | tail] -> [?[, tail, ?]]
    end
  end

  def encode(collection, true, options) do
    indent = indent(options)
    offset = offset(options) + indent
    options = offset(options, offset)

    fun = &[",\n", spaces(offset), JOSE.Poison.LexicalEncoder.encode(&1, options)]

    case Enum.flat_map(collection, fun) do
      [] -> "[]"
      [_ | tail] -> ["[\n", tail, ?\n, spaces(offset - indent), ?]]
    end
  end
end

if Application.get_env(:poison, :enable_hashdict) do
  defimpl JOSE.Poison.LexicalEncoder, for: HashDict do
    alias JOSE.Poison.LexicalEncoder

    use JOSE.Poison.LexicalPretty
    use JOSE.Poison.LexicalEncode

    def encode(dict, options) do
      if HashDict.size(dict) < 1 do
        "{}"
      else
        encode(dict, pretty(options), options)
      end
    end

    def encode(dict, false, options) do
      fun = fn {key, value} ->
        [?,, LexicalEncoder.BitString.encode(encode_name(key), options), ?:,
             LexicalEncoder.encode(value, options)]
      end

      [?{, tl(Enum.flat_map(dict, fun)), ?}]
    end

    def encode(dict, true, options) do
      indent = indent(options)
      offset = offset(options) + indent
      options = offset(options, offset)

      fun = fn {key, value} ->
        [",\n", spaces(offset), LexicalEncoder.BitString.encode(encode_name(key), options), ": ",
                                LexicalEncoder.encode(value, options)]
      end

      ["{\n", tl(Enum.flat_map(dict, fun)), ?\n, spaces(offset - indent), ?}]
    end
  end
end

if Version.match?(System.version, ">=1.3.0-rc.1") do
  defimpl JOSE.Poison.LexicalEncoder, for: [Date, Time, NaiveDateTime, DateTime] do
    def encode(value, options) do
      JOSE.Poison.LexicalEncoder.BitString.encode(@for.to_iso8601(value), options)
    end
  end
end

defimpl JOSE.Poison.LexicalEncoder, for: Any do
  defmacro __deriving__(module, struct, options) do
    deriving(module, struct, options)
  end

  def deriving(module, _struct, options) do
    only = options[:only]
    except = options[:except]

    extractor = cond do
      only ->
        quote(do: Map.take(struct, unquote(only)))
      except ->
        except = [:__struct__ | except]
        quote(do: Map.drop(struct, unquote(except)))
      true ->
        quote(do: :maps.remove(:__struct__, struct))
    end

    quote do
      defimpl JOSE.Poison.LexicalEncoder, for: unquote(module) do
        def encode(struct, options) do
          JOSE.Poison.LexicalEncoder.Map.encode(unquote(extractor), options)
        end
      end
    end
  end

  def encode(%{__struct__: _} = struct, options) do
    JOSE.Poison.LexicalEncoder.Map.encode(Map.from_struct(struct), options)
  end

  def encode(value, _options) do
    module =
      if Code.ensure_loaded?(Poison) do
        Poison.EncodeError
      else
        JOSE.Poison.LexicalEncodeError
      end
    raise module, value: value
  end
end

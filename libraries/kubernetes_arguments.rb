# Parses individual argv tokens without treating another flag as a value.
module ::KubernetesArguments
  module_function

  def parse(tokens, boolean_flags = [])
    tokens.each_with_index.each_with_object({}) do |(token, index), flags|
      match = token.to_s.match(/\A--([^=\s]+)(?:=(.*))?\z/)
      next unless match

      name, value = match.captures
      value = following_value(tokens[index + 1], boolean_flags.include?(name)) if value.nil?
      flags[name] = value
    end
  end

  def following_value(token, boolean)
    return 'true' if boolean
    return '' unless token.is_a?(String) && !token.empty? && !token.start_with?('-')

    token
  end

  def path?(value)
    value.is_a?(String) && value.start_with?('/') && !value.match?(/[\x00\r\n]/)
  end

  def duration(value)
    text = value.to_s
    parts = text.scan(/(\d+(?:\.\d+)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)/)
    return nil if parts.empty? || parts.flatten.join != text

    units = { 'h' => 3600, 'm' => 60, 's' => 1, 'ms' => 1e-3, 'us' => 1e-6, 'µs' => 1e-6, 'μs' => 1e-6, 'ns' => 1e-9 }
    parts.sum { |number, unit| number.to_f * units.fetch(unit) }
  end
end

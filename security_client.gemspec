lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "security_client/version"

Gem::Specification.new do |spec|
  spec.name          = "security_client"
  spec.version       = SecurityClient::VERSION
  spec.authors       = ["vinaymehta"]
  spec.email         = ["vinay.ymca@gmail.com"]

  spec.summary       = %q{Ubiq Security ruby client}
  spec.homepage      = "https://github.com/vinaymehta/security_client"
  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency 'httparty', '~> 0.13.7'
end

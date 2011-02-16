# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "declarative_authorization-dta"
  s.version = "0.1.1"

  s.required_ruby_version = ">= 1.8.6"
  s.authors = ["Jan Luehr"]
  s.summary = "declarative_authorization is a Rails plugin for authorization based on readable authorization rules."
  s.email = "yanosz@gmx.net"
  s.files = %w{CHANGELOG MIT-LICENSE README.rdoc Rakefile authorization_rules.dist.rb garlic_example.rb init.rb} + Dir["app/**/*.rb"] + Dir["app/**/*.erb"] + Dir["config/*"] + Dir["lib/*.rb"] + Dir["lib/**/*.rb"] + Dir["lib/tasks/*"] + Dir["test/*"]
  s.has_rdoc = true
  s.extra_rdoc_files = ['README.rdoc', 'CHANGELOG']
  s.homepage = %q{http://github.com/yanosz/declarative_authorization}

  s.add_dependency('rails', '>= 2.1.0')
end